# Especificación del protocolo

> Documento **normativo**: cliente, servidor y tests implementan exactamente lo que dice aquí.
> «DEBE» / «NO DEBE» son obligatorios; «PUEDE» es opcional. Cualquier cambio entra por PR.
> Identificador de protocolo: `merkle-audit/1`.

## 1. Alcance y garantía declarada

**Garantía.** Si una auditoría termina en `PASS`, entonces (salvo una colisión de SHA-256) cada uno de los `q` bloques consultados que devolvió el servidor es idéntico al bloque de esa posición en la versión del archivo comprometida en el manifiesto. Si el servidor no puede entregar correctos `d` de los `n` bloques, una auditoría los detecta con probabilidad exacta `P(n, d, q) = 1 − C(n−d, q) / C(n, q)` (§10).

**No se garantiza:**
- Que el archivo completo esté disponible o sea recuperable. No es un PoR (Juels-Kaliski, Shacham-Waters): no hay extractor, ni códigos de borrado, ni autenticadores homomórficos.
- Nada sobre los bloques no consultados en una auditoría concreta.
- Que los datos sigan intactos después de la última auditoría.
- Disponibilidad del servicio o tiempo de respuesta. Un timeout da `INCOMPLETE` (§8) y no cuenta como evidencia.
- Confidencialidad: los bloques se guardan y viajan en claro.
- Que el servidor guarde los datos él mismo. Puede obtenerlos de otra fuente en el momento de responder (§2).

Una serie de auditorías exitosas es evidencia probabilística (§10.3), no una prueba de disponibilidad completa.

## 2. Modelo de adversario

**Adversario: el servidor.** Es malicioso y adaptativo, y controla el canal con el cliente. Puede:
- borrar, modificar, truncar, reordenar o reemplazar bloques y nodos del árbol que guarda;
- conservar versiones anteriores y responder con ellas;
- responder con contenido arbitrario: caminos de otro índice, respuestas parciales, duplicadas o de una auditoría anterior;
- ver todos los desafíos pasados antes de decidir qué datos conservar.

**Suposiciones:**
1. SHA-256 es resistente a colisiones (Boneh-Shoup, Def. 8.1).
2. HMAC-SHA256 es un MAC seguro bajo la clave local del cliente.
3. Los índices salen de un CSPRNG (`secrets.SystemRandom`) y el servidor no los predice antes de recibir el desafío.
4. La máquina del cliente es confiable: el manifiesto, la clave HMAC y la bitácora no los toca el adversario. Esa es la «memoria de solo lectura» de Boneh-Shoup §8.1.
5. La carga inicial (§7.2) ocurre con el servidor honesto. La corrupción empieza después.

**Fuera del modelo:** disponibilidad y denegación de servicio, un servidor que recupera los datos de otra fuente al responder, canales laterales, un cliente comprometido y fallos del cliente durante la carga.

## 3. Primitivas y parámetros

| Símbolo | Valor | Notas |
|---|---|---|
| `H` | SHA-256 (`hashlib.sha256`), 32 bytes de salida | Único algoritmo. No hay negociación ni campo `alg` |
| `MAC` | HMAC-SHA256 (`hmac`) | Clave `K` de 32 bytes de `secrets.token_bytes(32)` |
| RNG de desafíos | `secrets.SystemRandom().sample(range(n), q)` | Sin reemplazo. Se prohíbe `random` en el camino del producto (ver §11.4 para experimentos) |
| `u64(x)` | entero sin signo, 8 bytes, big-endian | Toda longitud, índice o contador que entra en un hash |
| `B` (`block_size`) | una de {4096, 8192, 16384, 32768, 65536} bytes; por defecto 4096 | Potencias de dos entre 4 y 64 KiB |
| `S` (`file_size`) | `0 ≤ S ≤ 524 288 000` (500 MiB) | |
| `n` | `⌈S / B⌉` | `n = 0` si `S = 0`. Máximo 128 000 con `B = 4096` |
| `q` | `0 ≤ q ≤ min(n, Q_MAX)`, `Q_MAX = 1024`; `q ≥ 1` si `n ≥ 1` | |
| `file_id` | 16 bytes aleatorios (`secrets.token_bytes(16)`) | Se genera en la primera carga y no cambia entre versiones |
| `version` | entero ≥ 1 | Cada nueva carga del mismo `file_id` usa `version` = última + 1 |
| `audit_id` | 16 bytes aleatorios | Uno nuevo por auditoría y nunca se reutiliza |

**Dónde viven los límites.** Todas las constantes de esta tabla se definen una sola vez, en `core/params.py`. Se configuran así:
- `B`, `q` y el timeout los elige el usuario en cada carga o auditoría, dentro de los rangos de la tabla.
- `Q_MAX` y el timeout por defecto se pueden cambiar por configuración.
- Los 500 MiB y el rango de 4 a 64 KiB son lo que pide el enunciado. Ampliarlos es cambiar una constante.

**Clave y almacenamiento del cliente.** El directorio de datos es `$MERKLE_AUDIT_HOME` (por defecto `./.merkle-audit-client/`). La clave va en `manifest.key`, con permisos `0600`. Se crea en el primer uso y **NO DEBE** aparecer en logs, bitácora ni mensajes.

**Almacenamiento del servidor.** El directorio de datos es `$MERKLE_AUDIT_SERVER_HOME` (por defecto `./.merkle-audit-server/`), con una base SQLite. Al cargar, el servidor guarda los bloques, los niveles del árbol y una copia íntegra de los bloques (§11.3). Los caminos se leen de los niveles guardados en la carga, no se recalculan a partir de los bloques: así, un bloque alterado da `ROOT_MISMATCH` y no un camino coherente con el dato alterado.

**Codificación textual de bytes** (mensajes y manifiesto):
- Hashes e identificadores: hex en minúsculas y de longitud exacta (64 caracteres para un hash, 32 para `file_id` o `audit_id`). Mayúsculas o una longitud distinta se rechazan.
- Bloques: base64 estándar (RFC 4648 §4) con relleno `=`, decodificado estricto (`base64.b64decode(s, validate=True)`).

## 4. Codificación del árbol de Merkle → `core/`

### 4.1 Funciones con separación de dominios

| Prefijo | Función | Entrada a `H` | Longitud de la entrada |
|---|---|---|---|
| `0x00` | `leaf(i, x)` | `0x00 ‖ u64(i) ‖ u64(\|x\|) ‖ x` | 17 + \|x\| |
| `0x01` | `node(l, r)` | `0x01 ‖ l ‖ r` | 65 |
| `0x02` | `EMPTY_ROOT` | `0x02 ‖ "empty"` (ASCII) | 6 |
| `0x03` | `commit(…)` | `0x03 ‖ file_id ‖ u64(version) ‖ u64(B) ‖ u64(S) ‖ u64(n) ‖ root` | 81 |

Esta es la **única** definición de hoja. La usan el cliente, el servidor, los tests y el informe (corrección #2).

### 4.2 Bloques
- El bloque `i` (para `0 ≤ i < n`) es `x_i = archivo[i·B : (i+1)·B]`.
- Longitud esperada: `L(i) = B` si `i < n−1`; `L(n−1) = S − (n−1)·B`, que cae en `[1, B]`.
- **NO DEBE** rellenarse el último bloque. Es corto y su longitud real entra en la hoja (corrección #5).

### 4.3 Construcción
```
nivel_0 = [leaf(i, x_i) para i en 0..n−1]
mientras len(nivel) > 1:
    siguiente = [node(nivel[2k], nivel[2k+1]) para cada par completo]
    si len(nivel) es impar: añadir nivel[−1] tal cual a siguiente   # se promueve
    nivel = siguiente
root = nivel[0]          si n ≥ 1
root = EMPTY_ROOT        si n = 0
C    = commit(file_id, version, B, S, n, root)
```
El nodo sin hermano **se promueve** sin volver a aplicar el hash (Boneh-Shoup, Ej. 8.9, Fig. 8.16). `C` generaliza la raíz final `h(raíz ‖ s)` del ejercicio: además de `n`, liga el archivo, la versión y los parámetros.

### 4.4 Por qué la codificación es inequívoca
- Hoja contra nodo interno: el primer byte es distinto (`0x00` y `0x01`).
- Posición y longitud: `i` y `|x|` entran con ancho fijo. Dos bloques en posiciones distintas, o un bloque y el mismo con ceros añadidos, dan hojas distintas.
- Niveles: la forma del árbol depende solo de `n`, y `n` está ligado en `C`. El verificador deriva qué hash va en cada nivel a partir de `(i, n)` (§6) y nunca del servidor. Una prueba falsa que verifique da una colisión de `H` en el mismo dominio y la misma posición (Thm 8.8).
- Contexto: `commit` liga `file_id`, `version`, `B`, `S` y `n`, todos de ancho fijo.

Justificación en el informe: binding de commitments con codificación inequívoca (`material_p7.pdf`, pág. 10) y Thm 8.8 + Ej. 8.9 de Boneh-Shoup.

### 4.5 Vectores de prueba
Con `file_id = 000102…0f` (bytes 0 a 15), `version = 1` y `B = 4096`:

| Archivo | `n` | `root` | `C` |
|---|---|---|---|
| vacío (0 B) | 0 | `840850734821db93d0578d224007ed370d3f7e149f1884179cdaa871e154096a` | `eb445fcec8b6e770cc02516062d3a29b5adbb3b6fb6b70e634a54a8d3aa54441` |
| 1 byte `0x00` | 1 | `b0ef53e122b3c40b579355219695430329f46c3b24936cbd734967780a609be2` | `a2cace423e09ef46d0cfeba6687a5c806a48a95819bdf58007ee4e8b8722d950` |
| 8292 B, byte `k` = `k mod 251` | 3 | `597db13ae70da526ae336c9f3206e5ad27d734b494436845cdbe78f801500e0f` | `45cecf6d1b16a5b78797abd66fcf769b69d82513d15160a6cbf4df1adf11bb98` |

`tests/unit/test_vectors.py` **DEBE** reproducir esta tabla.

## 5. Manifiesto → `core/`

### 5.1 Campos
```json
{
  "format": "merkle-audit/manifest",
  "format_version": 1,
  "file_id": "<hex 32>",
  "version": 1,
  "file_name": "datos.bin",
  "file_size": 8292,
  "block_size": 4096,
  "n_blocks": 3,
  "root": "<hex 64>",
  "commitment": "<hex 64>",
  "created_at": "2026-11-18T20:15:00Z",
  "mac": "<hex 64>"
}
```
`file_name` y `created_at` son informativos (no entran en `C`), pero sí los cubre el MAC.

### 5.2 Serialización canónica y MAC
- `canon(m)` es `json.dumps(m sin "mac", sort_keys=True, separators=(",", ":"), ensure_ascii=True)` codificado en UTF-8.
- `mac = HMAC-SHA256(K, "merkle-audit/manifest/1" ‖ 0x00 ‖ canon(m))`, en hex.
- La comparación usa `hmac.compare_digest`.

### 5.3 Validación al cargar (antes de cada auditoría)
Se aplica en este orden. Cualquier fallo da `INVALID` y **no se envía el desafío** (corrección #9):
1. JSON válido, `format` y `format_version` conocidos, todos los campos presentes y con el tipo correcto → si no, `MANIFEST_FORMAT`.
2. El MAC verifica → si no, `MANIFEST_MAC`.
3. `block_size` permitido, `file_size` en rango, `n_blocks = ⌈file_size / block_size⌉` → si no, `MANIFEST_FORMAT`.
4. `commitment = commit(file_id, version, block_size, file_size, n_blocks, root)` → si no, `MANIFEST_COMMITMENT`.

### 5.4 Versiones
- Se guarda un manifiesto por `(file_id, version)`: `manifests/<file_id>/<version>.json`. La versión activa es la mayor.
- El cliente **NO** conserva el archivo después de la carga (corrección #17).

## 6. Pruebas de inclusión → `core/`

### 6.1 Forma del camino
La dirección de cada hermano se deriva de `(i, n)` y **nunca** del servidor (corrección #8):
```python
def path_shape(i, n):  # lista de LEFT/RIGHT, de la hoja hacia la raíz
    shape, idx, width = [], i, n
    while width > 1:
        if idx % 2 == 1:
            shape.append(LEFT)  # el hermano está a la izquierda
        elif idx + 1 < width:
            shape.append(RIGHT)  # el hermano está a la derecha
        # si no: el nodo se promueve en este nivel y no aporta hermano
        idx, width = idx // 2, (width + 1) // 2
    return shape
```
El camino es la lista de hashes de los hermanos en ese orden, con `len(path) = len(path_shape(i, n)) ≤ ⌈log2 n⌉`.

### 6.2 Verificación de un bloque
Entradas: `i`, `x`, `path` y el manifiesto validado (`n`, `B`, `S`, `root`).
1. `|x| = L(i)` → si no, `BLOCK_LENGTH`.
2. `len(path) = len(path_shape(i, n))` → si no, `PATH_LENGTH`.
3. `h = leaf(i, x)`. Para cada `(s, dir)`: `h = node(s, h)` si `dir = LEFT`; si es `RIGHT`, `h = node(h, s)`.
4. `compare_digest(h, root)` → si no, `ROOT_MISMATCH`.

Las multipruebas (Boneh-Shoup, Thm 8.7) quedan fuera de esta versión del protocolo y son una posible optimización del ancho de banda.

## 7. Mensajes del protocolo → `protocol/`

### 7.1 Transporte
HTTP local (FastAPI + httpx), sin prefijo de versión en las rutas: la versión del protocolo va en el cuerpo. Los cuerpos JSON llevan `"protocol": "merkle-audit/1"` y `"type"`. Un mensaje con un `protocol` desconocido, campos de más o de menos, o tipos incorrectos es `MALFORMED`. Los modelos pydantic usan `extra="forbid"`.

### 7.2 Carga
`PUT /files/{file_id}/versions/{version}?block_size=B&file_size=S`, con el archivo crudo como cuerpo (`application/octet-stream`; no es JSON).

1. El servidor comprueba los parámetros (§3) y que el cuerpo mida exactamente `S`. Si no, devuelve `400 BAD_REQUEST`. Si `(file_id, version)` ya existe, `409 VERSION_EXISTS`: las versiones son inmutables. Si no existe pero `version` no es la última guardada + 1 (o `1` para un `file_id` nuevo), `400 BAD_REQUEST`.
2. El servidor parte en bloques, guarda bloques y niveles del árbol, y responde `201` con:
   ```json
   {"protocol": "merkle-audit/1", "type": "upload_receipt",
    "file_id": "…", "version": 1, "n_blocks": 3, "root": "…", "commitment": "…"}
   ```
3. El cliente calcula su propio árbol mientras envía el archivo. Solo crea el manifiesto si el recibo coincide en `n_blocks`, `root` y `commitment`. Si no coincide, la carga falla y no queda manifiesto.

### 7.3 Desafío
`POST /audit`:
```json
{"protocol": "merkle-audit/1", "type": "challenge",
 "audit_id": "<hex 32>", "file_id": "<hex 32>", "version": 2,
 "commitment": "<hex 64>", "indices": [5, 17, 802]}
```
`indices` son distintos, están en `[0, n)` y van en orden ascendente. Si `n = 0`, `indices = []`.

### 7.4 Respuesta
```json
{"protocol": "merkle-audit/1", "type": "response",
 "audit_id": "…", "file_id": "…", "version": 2,
 "proofs": [
   {"index": 5,  "block": "<base64>", "path": ["<hex 64>", "…"]},
   {"index": 17, "block": null,       "path": []}
 ]}
```
- `proofs` va en el mismo orden que `indices`, con una entrada por índice.
- `"block": null` significa que el servidor declara que no tiene ese bloque. En ese caso `path` va vacío.

### 7.5 Error del servidor
```json
{"protocol": "merkle-audit/1", "type": "error", "audit_id": "…" | null,
 "code": "UNKNOWN_FILE" | "UNKNOWN_VERSION" | "COMMITMENT_MISMATCH" | "BAD_REQUEST" | "VERSION_EXISTS" | "INTERNAL"}
```
Un servidor honesto responde `COMMITMENT_MISMATCH` cuando su `C` para `(file_id, version)` no coincide con el del desafío, y `BAD_REQUEST` si `q > Q_MAX`, si los índices no cumplen §7.3 o si el cuerpo no es un mensaje válido (en ese caso `audit_id` es `null`).

### 7.6 Códigos HTTP
Toda respuesta del servidor lleva un cuerpo JSON de §7.2, §7.4 o §7.5. El código HTTP acompaña al mensaje, pero el cliente evalúa el cuerpo (§8), no el código.

| Código | Cuerpo |
|---|---|
| `200` | `response` |
| `201` | `upload_receipt` |
| `400` | `BAD_REQUEST` |
| `404` | `UNKNOWN_FILE`, `UNKNOWN_VERSION` |
| `409` | `VERSION_EXISTS`, `COMMITMENT_MISMATCH` |
| `500` | `INTERNAL` |

## 8. Reglas de aceptación y estados de una auditoría → `protocol/`

### 8.1 Estados
| Estado | Significado | ¿Cuenta como detección? |
|---|---|---|
| `PASS` | Las `q` pruebas verifican. Con `n = 0` se marca `trivial: true` | No |
| `CORRUPT` | Respuesta bien formada y ligada al desafío, pero al menos un bloque falla, o el servidor declara que no tiene el archivo | Sí |
| `INVALID` | Manifiesto inválido, o respuesta mal formada o no ligada al desafío (incluye el rollback de versión declarado) | Sí: el servidor no cumplió el protocolo |
| `INCOMPLETE` | Timeout (60 s por defecto, configurable) o error de conexión. No hay evidencia en ningún sentido | No |

### 8.2 Orden de evaluación
1. Validar el manifiesto (§5.3).
2. Enviar el desafío y esperar, o terminar en `INCOMPLETE`.
3. Validar la estructura y la ligadura de la respuesta. El primer fallo da `INVALID` y no se verifican pruebas.
4. Verificar **todas** las pruebas (§6.2), sin parar en la primera que falle. Si alguna falla, el estado es `CORRUPT` con la lista de `(índice, causa)`.

### 8.3 Lista cerrada de causas
| Código | Estado | Condición |
|---|---|---|
| `MANIFEST_FORMAT` | INVALID | §5.3 pasos 1 o 3 |
| `MANIFEST_MAC` | INVALID | El MAC del manifiesto no verifica |
| `MANIFEST_COMMITMENT` | INVALID | `C` no corresponde a los campos |
| `MALFORMED` | INVALID | JSON, esquema, hex o base64 inválidos, o `type` inesperado |
| `AUDIT_ID_MISMATCH` | INVALID | `audit_id` ≠ el del desafío en curso (incluye replay de una auditoría anterior) |
| `FILE_ID_MISMATCH` | INVALID | `file_id` ≠ el del desafío |
| `VERSION_MISMATCH` | INVALID | `version` ≠ la del desafío (rollback declarado) |
| `INDEX_SET_MISMATCH` | INVALID | `[p.index for p in proofs] ≠ indices`: falta, sobra o se duplica un índice, aparece uno ∉ Q o el orden es otro |
| `SERVER_ERROR` | INVALID | Error `COMMITMENT_MISMATCH`, `BAD_REQUEST` o `INTERNAL` (se guarda el `code`) |
| `FILE_MISSING` | CORRUPT | Error `UNKNOWN_FILE` o `UNKNOWN_VERSION` |
| `BLOCK_MISSING` | CORRUPT | `block = null` |
| `BLOCK_LENGTH` | CORRUPT | `\|x\| ≠ L(i)` |
| `PATH_LENGTH` | CORRUPT | `len(path) ≠ len(path_shape(i, n))` |
| `ROOT_MISMATCH` | CORRUPT | La raíz recomputada ≠ `root` del manifiesto (modificado, reemplazado, camino cruzado o rollback no declarado) |
| `TIMEOUT` | INCOMPLETE | Se superó el tiempo de espera |
| `CONNECTION` | INCOMPLETE | Error de red o HTTP sin cuerpo válido |

No hay otras causas. Un caso nuevo exige cambiar esta tabla y §12.

## 9. Bitácora y programador de auditorías → `client/`

### 9.1 Registro por auditoría
Se usa SQLite en el directorio del cliente, tabla `audits`, solo de inserción. Cada fila guarda:
- **Identidad:** `audit_id`, `file_id`, `version`, `commitment`, `protocol`, versión del paquete.
- **Parámetros:** `n`, `q`, `block_size`, `file_size`, `timeout_s` y el origen (`manual` o `schedule:<id>`).
- **Desafío:** la lista completa de `indices`.
- **Resultado:** `status`, `trivial`, lista de `(index, cause)` y `server_error_code` si lo hay.
- **Evidencia:** por índice, `leaf` y raíz recomputadas en hex (o la causa si no se pudieron calcular); `sha256` del cuerpo crudo de la respuesta.
- **Costo:** `started_at`, `finished_at` (UTC, RFC 3339), latencia en ms, bytes del desafío y de la respuesta, y tiempo de verificación en ms.
- **Contexto teórico:** `P(n, d, q)` para `d = ⌈ε·n⌉` con ε ∈ {1, 5, 10, 25} %.

**NO** se guardan el contenido de los bloques ni la clave. Con `--keep-responses`, el cuerpo crudo de la respuesta se guarda en `responses/<audit_id>.json`, de modo que `merkle-audit reverify <audit_id>` repite la verificación con el mismo manifiesto. Esta opción es solo para datos sintéticos.

### 9.2 Programador
`merkle-audit schedule add --file-id … --every 10m --q 300` (o `--target-eps 0.01 --confidence 0.99`, §10.2). Cada ejecución es una auditoría normal con índices nuevos y queda registrada con `origin = schedule:<id>`. Los programas se guardan en la tabla `schedules`.

## 10. Modelo probabilístico → `core/probability`

### 10.1 Probabilidad de detección
Si `d` de los `n` bloques están dañados y se consultan `q` índices uniformes sin reemplazo:
```
P(n, d, q) = 1 − C(n−d, q) / C(n, q) = 1 − Π_{j=0}^{q−1} (n−d−j)/(n−j)
```
- La implementación usa la forma de producto en `float`. Los tests la comparan con `math.comb` y `fractions.Fraction` para `n ≤ 2000`.
- Casos borde: `P = 1` si `q > n−d`; `P = 0` si `d = 0` o `q = 0`.
- `1 − (1−ε)^q` es la aproximación **con** reemplazo. Solo aparece en el informe como comparación (corrección #3).
- La fórmula es exacta en este modelo: el servidor fija qué bloques pierde antes de ver el desafío y no puede predecirlo (§2, suposición 3).

### 10.2 Elección de `q`
`q_min(n, d, 1−δ)` es el menor `q` con `P(n, d, q) ≥ 1−δ`. Se encuentra por búsqueda binaria, porque `P` crece con `q`. Por defecto el objetivo es `ε = 1 %` con `1−δ = 99 %`; para `n = 10 000` eso da `q = 448` (`P = 99,002 %`). La aproximación con reemplazo pediría 459.

### 10.3 Repetición
Con `k` auditorías independientes (índices nuevos en cada una) y daño estático, la probabilidad de no detectar es `(1 − P(n, d, q))^k`. Esto no prueba disponibilidad: el daño puede ocurrir después de la última auditoría, un daño de un solo bloque se detecta por auditoría con probabilidad `q/n`, y los bloques nunca consultados no tienen ninguna garantía.

### 10.4 Costo
Bytes de la respuesta ≈ `Σ_i (4·⌈L(i)/3⌉ + 67·len(path_i)) + sobrecarga JSON`, frente a `S` bytes para descargar el archivo completo. La interfaz muestra `P` y el costo en función de `q`.

### 10.5 Criterio de los experimentos
Para cada combinación `(n, d, q)` se declaran `n`, `d`, `q` y `N`. La tasa empírica `p̂` se acepta si `P(n, d, q)` cae en el intervalo de Wilson al 99 % de `p̂`. Se reporta cuántas combinaciones fallan: se espera ≈1 %.

## 11. Inyector de fallos → `server/`

### 11.1 Principio
Actúa solo sobre el almacenamiento del servidor, nunca sobre el cliente (corrección #17). Es un CLI aparte (`merkle-audit-fault`) que escribe en el directorio de datos del servidor. No tiene endpoint de red.

### 11.2 Operaciones
Toda operación recibe `--file <file_id en hex>` y `--version v` (por defecto, la última versión cargada) y actúa solo sobre esa versión, salvo `drop-file` y `reset`, que actúan sobre todas las versiones del archivo.

| Operación | Efecto | Causa esperada |
|---|---|---|
| `delete --indices …` | Borra los bloques. El servidor responde `block: null` | `BLOCK_MISSING` |
| `modify --indices … [--mode bitflip\|truncate]` | Invierte un bit en un desplazamiento aleatorio, o quita el último byte | `ROOT_MISMATCH` / `BLOCK_LENGTH` |
| `replace --index i --with j` | El contenido del bloque `i` pasa a ser el del bloque `j` | `ROOT_MISMATCH` |
| `cross-path --index i --with j` | Para `i`, el servidor responde con el camino de `j` | `ROOT_MISMATCH` o `PATH_LENGTH` |
| `rollback --to v' [--declare\|--lie]` | Responde a la versión `v` con los datos de `v' < v`. Con `--declare` envía `version = v'`; con `--lie`, `version = v`. Un índice que no existe en `v'` se responde con `block: null` | `VERSION_MISMATCH` / `ROOT_MISMATCH` (o `BLOCK_MISSING`) |
| `damage --eps ε --op delete\|modify` | Daña `d = ⌈ε·n⌉` índices elegidos con la semilla | Según `op` |
| `drop-file` | Borra los datos vivos del archivo. La copia íntegra se conserva | `FILE_MISSING` |
| `reset` | Restaura los bloques desde la copia íntegra y desactiva las faltas de respuesta | — |

### 11.3 Reproducibilidad
- Toda operación aleatoria acepta `--seed` (si no se da, se genera una y se imprime). Usa `random.Random(seed)`.
- Cada aplicación se registra en la tabla `faults` del servidor con la operación, los parámetros, la semilla, los índices afectados y la hora.
- El servidor guarda una copia íntegra al cargar para que `reset` funcione. Las faltas de respuesta (`cross-path`, `rollback`) se guardan en `faults` y la capa de respuesta las consulta.

### 11.4 RNG en experimentos
Solo el harness de `experiments/` **PUEDE** inyectar un `random.Random(seed)` como fuente de índices, para que los resultados se puedan repetir. La semilla se guarda con los resultados. El CLI y la interfaz **NO DEBEN** exponer esa opción.

## 12. Trazabilidad a pruebas

| Requisito / causa | Test |
|---|---|
| Vectores §4.5 | `tests/unit/test_vectors.py` |
| Forma del camino §6.1 (propiedad: verifica para todo `i < n ≤ 300`) | `tests/unit/test_merkle.py` (hypothesis) |
| `P` exacta §10.1 y `q_min` §10.2 | `tests/unit/test_probability.py` |
| Archivo intacto, vacío y con tamaño no múltiplo de `B` | `tests/integration/test_server_api.py`, `tests/integration/test_client.py` |
| `MANIFEST_FORMAT`, `MANIFEST_MAC`, `MANIFEST_COMMITMENT` | `tests/adversarial/test_manifest_tampering.py` |
| `MALFORMED` | `tests/adversarial/test_malformed.py` |
| `AUDIT_ID_MISMATCH` (replay) | `tests/adversarial/test_replay.py` |
| `FILE_ID_MISMATCH` | `tests/adversarial/test_binding.py` |
| `VERSION_MISMATCH`, rollback `--lie` | `tests/adversarial/test_rollback.py` |
| `INDEX_SET_MISMATCH` (falta, sobra, duplicado, ajeno, orden) | `tests/adversarial/test_index_set.py` |
| `SERVER_ERROR`, `FILE_MISSING` | `tests/adversarial/test_server_errors.py` |
| `BLOCK_MISSING` (borrado) | `tests/adversarial/test_delete.py` |
| `BLOCK_LENGTH`, `ROOT_MISMATCH` (modificado) | `tests/adversarial/test_modify.py` |
| `ROOT_MISMATCH` (reemplazado) | `tests/adversarial/test_replace.py` |
| `ROOT_MISMATCH` / `PATH_LENGTH` (camino cruzado) | `tests/adversarial/test_cross_path.py` |
| `TIMEOUT`, `CONNECTION` | `tests/integration/test_client.py` |
| Manifiesto inválido: no se envía el desafío (§5.3) | `tests/integration/test_client.py` |
| Bitácora solo de inserción, programador y `reverify` (§9) | `tests/integration/test_client.py` |
| Experimentos §10.5 | `experiments/run_detection.py` (fuera de CI) |
