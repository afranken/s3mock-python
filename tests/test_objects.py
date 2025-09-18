import inspect
import types
from typing import cast

import pytest
from botocore.exceptions import ClientError

from s3mock_test import UPLOAD_FILE_NAME, get_bucket_name

def test_put_get_delete_object(s3_client):
    this_function_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name
    bucket_name = get_bucket_name(this_function_name)

    s3_client.create_bucket(Bucket=bucket_name)
    with open(UPLOAD_FILE_NAME, 'rb') as file:
        blob: bytes = file.read()
        s3_client.put_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, Body=blob)

    get_object = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)
    assert get_object is not None

    s3_client.delete_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)

    with pytest.raises(ClientError):
        _ = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)
