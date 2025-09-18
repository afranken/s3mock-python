import re
import time

import boto3
import pytest
from botocore.client import Config
from mypy_boto3_s3.client import S3Client
from testcontainers.core.container import DockerContainer  # type: ignore[import-untyped]
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

UPLOAD_FILE_NAME = 'testfile.txt'


def get_bucket_name(function_name: str) -> str:
    return f'{function_name[:50]}-{time.time()}'.replace('_', '-')

container = DockerContainer("adobe/s3mock:4.8.0").with_exposed_ports(9090, 9191).with_env("debug", "true")

# Constants used for S3 client configuration (moved from TestS3Mock to module scope)
_AWS_ACCESS_KEY = 'dummy-key'
_AWS_SECRET_ACCESS_KEY = 'dummy-key'
_AWS_SESSION_TOKEN = 'dummy-key'
_CONNECTION_TIMEOUT = 1
_READ_TIMEOUT = 60  # AWS default
_MAX_RETRIES = 3

@pytest.fixture(scope="session", autouse=True)
def s3mock_container():
    # Start the container once per test session; Ryuk will stop it afterward
    container.waiting_for(LogMessageWaitStrategy(re.compile(r'.*Started S3MockApplication.*')))
    container.start()

@pytest.fixture(scope="session")
def endpoint_url(s3mock_container) -> str:
    ip = container.get_container_host_ip()
    port = container.get_exposed_port(9090)
    return f'http://{ip}:{port}'

@pytest.fixture(scope="session", autouse=True)
def s3_client(endpoint_url) -> S3Client:
    config = Config(
        connect_timeout=_CONNECTION_TIMEOUT,
        read_timeout=_READ_TIMEOUT,
        retries={'max_attempts': _MAX_RETRIES},
        signature_version='s3v4',
        s3={'addressing_style': 'path'},
    )
    return boto3.client(
        's3',
        aws_access_key_id=_AWS_ACCESS_KEY,
        aws_secret_access_key=_AWS_SECRET_ACCESS_KEY,
        aws_session_token=_AWS_SESSION_TOKEN,
        config=config,
        endpoint_url=endpoint_url,
    )
