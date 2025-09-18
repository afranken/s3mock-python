# S3Mock python test

Tests the [Adobe S3Mock](https://github.com/adobe/S3Mock) with [Testcontainers](https://testcontainers.com/) in Python.

Contains a reimplementation of the integration tests in https://github.com/adobe/S3Mock/blob/main/integration-tests/

## Requirements
- Python 3.9+
- [uv](https://docs.astral.sh/uv/) (fast Python package/dependency manager)
- Docker (required by testcontainers to run the S3Mock container)

## Quick start

```bash
# Create a local .venv and install dependencies
uv sync --group dev --no-install-project

# Run the tests
uv run --no-project pytest -q

# Or just use make (wraps uv)
make
```

## Make targets
- make venv — create venv and install deps via uv
- make test — run tests
- make lint — run ruff
- make typecheck — run mypy
- make (default) — venv + test

## Notes
- Dependency management has been migrated to pyproject.toml (PEP 621). Use uv instead of pip/requirements.txt.
