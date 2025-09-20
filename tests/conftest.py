# Re-export fixtures so pytest can discover them in this conftest regardless of file location.
import sys
from pathlib import Path

from s3mock_test import endpoint_url, s3_client, s3mock_container  # noqa: F401

# Ensure the project root is on sys.path so `import s3mock_test` works
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Expose fixtures defined in s3mock_test.py to all tests in this package
pytest_plugins = ["s3mock_test"]
