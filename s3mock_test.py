import base64
import hashlib
import re
import time
from typing import Iterable, Optional

import boto3
import pytest
from botocore.client import Config
from botocore.exceptions import ClientError
from mypy_boto3_s3.client import S3Client
from testcontainers.core.container import DockerContainer  # type: ignore[import-untyped]
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

UPLOAD_FILE_NAME = 'testfile.txt'

container = DockerContainer("adobe/s3mock:4.8.0").with_exposed_ports(9090, 9191).with_env("debug", "true")

# Constants used for S3 client configuration (moved from TestS3Mock to module scope)
_AWS_ACCESS_KEY = 'dummy-key'
_AWS_SECRET_ACCESS_KEY = 'dummy-key'
_AWS_SESSION_TOKEN = 'dummy-key'
_CONNECTION_TIMEOUT = 1
_READ_TIMEOUT = 60  # AWS default
_MAX_RETRIES = 3

@pytest.fixture(scope="function", autouse=True)
def test_name(request) -> str:
    # Prefer originalname; fall back to name if unavailable
    return getattr(request.node, "originalname", request.node.name)

@pytest.fixture(scope="function", autouse=True)
def bucket_name(test_name: str) -> str:
    return f'{test_name[:50]}-{time.time()}'.replace('_', '-')

@pytest.fixture(autouse=True)
def cleanup(s3_client: S3Client):
    print("Setup")
    # currently, nothing to do here.
    yield
    print("Teardown")
    # clean up all resources created during the test
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        name = bucket['Name']
        delete_multipart_uploads(s3_client, name)
        delete_objects_in_bucket(s3_client, name, object_lock_enabled=False)
        s3_client.delete_bucket(Bucket=name)

@pytest.fixture(scope="session", autouse=True)
def s3mock_container():
    # Start the container once per test session; Ryuk will stop it afterward
    container.waiting_for(LogMessageWaitStrategy(re.compile(r'.*Started S3MockApplication.*')))
    container.start()

@pytest.fixture(scope="session")
def endpoint_url(s3mock_container) -> str:
    ip = container.get_container_host_ip()
    port = container.get_exposed_port(9191)
    return f'https://{ip}:{port}'

@pytest.fixture(scope="session")
def endpoint_url_http(s3mock_container) -> str:
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
        verify=False,  # Skip SSL certificate verification (use only in tests)
    )

@pytest.fixture(scope="session", autouse=True)
def s3_client_http(endpoint_url_http) -> S3Client:
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
        endpoint_url=endpoint_url_http,
    )

def delete_multipart_uploads(s3_client: S3Client, bucket_name: str) -> None:
    """
    Abort all in-progress multipart uploads in the specified bucket.
    Mirrors the behavior of the provided Kotlin snippet.
    """
    key_marker: Optional[str] = None
    upload_id_marker: Optional[str] = None

    while True:
        params = {"Bucket": bucket_name}
        if key_marker is not None:
            params["KeyMarker"] = key_marker
        if upload_id_marker is not None:
            params["UploadIdMarker"] = upload_id_marker

        resp = s3_client.list_multipart_uploads(**params)

        for upload in (resp.get("Uploads") or []):
            s3_client.abort_multipart_upload(
                Bucket=bucket_name,
                Key=upload["Key"],
                UploadId=upload["UploadId"],
            )

        if not resp.get("IsTruncated"):
            break

        key_marker = resp.get("NextKeyMarker")
        upload_id_marker = resp.get("NextUploadIdMarker")

def delete_objects_in_bucket(s3_client: S3Client, bucket_name: str, object_lock_enabled: bool) -> None:
    """
    Delete all object versions and delete markers in the bucket.
    If object lock is enabled, clear any potential legal holds before deletion.
    """
    paginator = s3_client.get_paginator("list_object_versions")
    page_iterator: Iterable[dict] = paginator.paginate(
        Bucket=bucket_name,
        EncodingType="url",
    )

    for page in page_iterator:
        # Handle object versions
        for version in page.get("Versions", []) or []:
            if object_lock_enabled:
                s3_client.put_object_legal_hold(
                    Bucket=bucket_name,
                    Key=version["Key"],
                    VersionId=version["VersionId"],
                    LegalHold={"Status": "OFF"},
                )
            s3_client.delete_object(
                Bucket=bucket_name,
                Key=version["Key"],
                VersionId=version["VersionId"],
            )

        # Handle delete markers
        for marker in page.get("DeleteMarkers", []) or []:
            if object_lock_enabled:
                s3_client.put_object_legal_hold(
                    Bucket=bucket_name,
                    Key=marker["Key"],
                    VersionId=marker["VersionId"],
                    LegalHold={"Status": "OFF"},
                )
            s3_client.delete_object(
                Bucket=bucket_name,
                Key=marker["Key"],
                VersionId=marker["VersionId"],
            )

def delete_bucket(s3_client: S3Client, bucket_name: str) -> None:
    """
    Delete the bucket and wait until it no longer exists.
    """
    s3_client.delete_bucket(Bucket=bucket_name)

    # Wait until the bucket is confirmed deleted
    waiter = s3_client.get_waiter("bucket_not_exists")
    waiter.wait(Bucket=bucket_name)

    # Optional parity with the Kotlin snippet's assertion: verify it's gone
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        raise AssertionError("Bucket still exists after deletion")
    except ClientError:
        # Expected: head_bucket should fail if the bucket no longer exists
        pass

def given_bucket(s3_client: S3Client, bucket_name: str) -> dict[str, str | int]:
    return s3_client.create_bucket(Bucket=bucket_name)

def given_object(s3_client: S3Client, bucket_name: str, object_name: str = UPLOAD_FILE_NAME) -> dict[str, str | int]:
    with open('testfile.txt', 'rb') as file:
        return s3_client.put_object(Bucket=bucket_name, Key=object_name, Body=file.read())

def compute_md5_etag(data: bytes) -> str:
    # S3 single-part ETag is the hex MD5 in quotes
    return f"\"{hashlib.md5(data).hexdigest()}\""


def compute_sha256_checksum_b64(data: bytes) -> str:
    # AWS returns base64-encoded checksum for SHA256
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
