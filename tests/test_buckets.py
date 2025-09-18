import inspect
import types
from typing import cast

from s3mock_test import get_bucket_name

def test_create_list_delete_bucket(s3_client):
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
