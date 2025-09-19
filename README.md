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

## Test against locally running S3Mock
To test against a locally running S3Mock, set these two environment variables:
* `S3MOCK_ENDPOINT` to the HTTPS endpoint of the S3Mock instance.
* `S3MOCK_ENDPOINT_HTTP` to the HTTP endpoint of the S3Mock instance.

Example:
```bash
docker run -p 9090:9090 -p 9191:9191 -v s3mock-test:/s3mock-test -e root=/s3mock-test -e validKmsKeys="arn:aws:kms:us-east-1:1234567890:key/valid-test-key-id" -e initialBuckets="bucket-a, bucket-b" -e SPRING_PROFILES_ACTIVE=debug -t adobe/s3mock:4.9.0
S3MOCK_ENDPOINT=https://localhost:9191 S3MOCK_ENDPOINT_HTTP=http://localhost:9090 make
```

## Notes
- Dependency management has been migrated to pyproject.toml (PEP 621). Use uv instead of pip/requirements.txt.
