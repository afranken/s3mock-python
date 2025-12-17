.PHONY: default ci venv test lint lint-fix typecheck

default: ci

ci: venv lint lint-fix typecheck test

venv:
	@uv sync

# Run tests
test:
	@uv run pytest -vv

# Lint with ruff
lint:
	@uv run ruff check .

# Fix simple lint errors with ruff
lint-fix:
	@uv run ruff check . --fix

# Type-check with ty
typecheck:
	@uv run ty check .
