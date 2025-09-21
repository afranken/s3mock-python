.PHONY: default ci venv test lint typecheck

default: ci

ci: venv lint typecheck test

venv:
	@uv sync --group dev --no-install-project

# Run tests
test:
	@uv run --no-project pytest -vv

# Lint with ruff
lint:
	@uv run --no-project ruff check .

# Fix simple lint errors with ruff
lint:
	@uv run --no-project ruff check . --fix

# Type-check with mypy
typecheck:
	@uv run --no-project mypy .