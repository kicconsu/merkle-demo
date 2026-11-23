.PHONY: sync test lint fmt check server ui demo experiments

sync:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff check --fix .
	uv run ruff format .

check: lint test

server:
	uv run uvicorn merkle_audit.server.app:app --reload

ui:
	uv run streamlit run src/merkle_audit/ui/app.py

demo:
	uv run python scripts/demo.py

experiments:
	uv run python experiments/run_detection.py
	uv run python experiments/run_costs.py
	uv run python experiments/plot_results.py
