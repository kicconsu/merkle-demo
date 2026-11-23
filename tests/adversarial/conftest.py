"""Fixtures compartidas por los tests de ataques."""

import pytest
from support import DATA_20, HonestStore, ServerHarness

from merkle_audit.protocol.challenge import new_challenge
from merkle_audit.server.faults import Injector


@pytest.fixture
def store():
    # 20 bloques, el último corto
    return HonestStore(DATA_20)


@pytest.fixture
def challenge(store):
    return new_challenge(store.manifest, 8)


# --- Servidor real con el inyector de fallos -----------------------------------------------------


@pytest.fixture
def server(tmp_path):
    return ServerHarness(tmp_path)


@pytest.fixture
def manifest(server):
    return server.upload(DATA_20)


@pytest.fixture
def injector(server):
    return Injector(server.store)
