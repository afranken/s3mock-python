.PHONY: default ci venv test lint typecheck

default: ci

ci: venv lint typecheck test

venv:
	@uv sync --group dev

# Run tests
test:
	@uv run pytest -vv

# Lint with ruff
lint:
	@uv run ruff check .

# Fix simple lint errors with ruff
lint:
	@uv run ruff check . --fix

# Type-check with mypy
typecheck:
	@uv run mypy .