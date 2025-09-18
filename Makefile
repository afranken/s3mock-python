.PHONY: default ci venv test lint typecheck

default: ci

ci: venv test

venv:
	@uv sync --group dev --no-install-project

# Run tests
test:
	@uv run --no-project pytest -q s3mock_test.py

# Lint with ruff
lint:
	@uv run --no-project ruff check .

# Type-check with mypy
typecheck:
	@uv run --no-project mypy .