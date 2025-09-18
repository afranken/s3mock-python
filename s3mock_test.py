import inspect
import time
import types
from typing import cast

import boto3
import pytest
from botocore.client import Config
from botocore.exceptions import ClientError
from mypy_boto3_s3.client import S3Client
from testcontainers.core.container import DockerContainer  # type: ignore[import-untyped]
from testcontainers.core.waiting_utils import wait_for_logs  # type: ignore[import-untyped]

UPLOAD_FILE_NAME = 'testfile.txt'


def get_bucket_name(function_name: str) -> str:
    return f'{function_name}-{time.time()}'.replace('_', '-')


class TestS3Mock:
    __AWS_ACCESS_KEY = 'dummy-key'
    __AWS_SECRET_ACCESS_KEY = 'dummy-key'
    __AWS_SESSION_TOKEN = 'dummy-key'
    __CONNECTION_TIMEOUT = 1
    __READ_TIMEOUT = 60  # AWS default
    __MAX_RETRIES = 3

    @pytest.fixture()
    def s3mock_container(self) -> DockerContainer:
        container = (DockerContainer("adobe/s3mock:4.8.0")
                     .with_exposed_ports(9090, 9191)
                     .with_env("debug", "true")
                     .start())
        _ = wait_for_logs(container, ".*Started S3MockApplication.*")
        yield container
        container.stop()

    @pytest.fixture()
    def endpoint_url(self, s3mock_container) -> str:
        ip = s3mock_container.get_container_host_ip()
        port = s3mock_container.get_exposed_port(9090)
        return f'http://{ip}:{port}'

    @pytest.fixture()
    def s3_client(self, s3mock_container, endpoint_url) -> S3Client:
        config = Config(connect_timeout=self.__CONNECTION_TIMEOUT,
                        read_timeout=self.__READ_TIMEOUT,
                        retries={'max_attempts': self.__MAX_RETRIES},
                        signature_version='s3v4',
                        s3={'addressing_style': 'path'})
        return boto3.client('s3',
                            aws_access_key_id=self.__AWS_ACCESS_KEY,
                            aws_secret_access_key=self.__AWS_SECRET_ACCESS_KEY,
                            aws_session_token=self.__AWS_SESSION_TOKEN,
                            config=config,
                            endpoint_url=endpoint_url)

    def test_create_list_delete_bucket(self, s3_client, endpoint_url):
        buckets = s3_client.list_buckets()
        assert len(buckets['Buckets']) == 0

        this_function_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name
        bucket_name = get_bucket_name(this_function_name)

        s3_client.create_bucket(Bucket=bucket_name)
        response = s3_client.list_buckets()
        assert len(response['Buckets']) == 1
        assert response['Buckets'][0]['Name'] == bucket_name

        s3_client.delete_bucket(Bucket=bucket_name)
        buckets = s3_client.list_buckets()
        assert len(buckets['Buckets']) == 0

    def test_put_get_delete_object(self, s3_client, endpoint_url):
        this_function_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name
        bucket_name = get_bucket_name(this_function_name)

        s3_client.create_bucket(Bucket=bucket_name)
        with open(UPLOAD_FILE_NAME, 'rb') as file:
            blob: bytes = file.read()
            s3_client.put_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, Body=blob)
            file.close()

        get_object = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)

        assert get_object is not None

        s3_client.delete_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)

        with pytest.raises(ClientError):
            _ = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)
