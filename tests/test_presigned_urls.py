import os
import tempfile

import requests

from s3mock_test import (
    UPLOAD_FILE_NAME,
    compute_md5_etag,
    given_bucket,
    random_name,
)

# Reimplementation of https://github.com/adobe/S3Mock/blob/main/integration-tests/src/test/kotlin/com/adobe/testing/s3mock/its/PresignedUrlIT.kt


def test_presigned_post_object(s3_client, bucket_name: str):
    given_bucket(s3_client, bucket_name)

    key = f"{random_name()}-{UPLOAD_FILE_NAME}"
    payload = os.urandom(20 * 1024 * 1024)
    expected_etag = compute_md5_etag(payload)
    tagging_xml = (
        '<Tagging><TagSet><Tag><Key>Tag Name</Key>'
        '<Value>Tag Value</Value></Tag></TagSet></Tagging>'
    )
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file_path = tmp_file.name
    try:
        tmp_file.write(payload)
        tmp_file.flush()
    finally:
        tmp_file.close()

    presigned = s3_client.generate_presigned_post(
        Bucket=bucket_name,
        Key=key,
        Fields={
            'Content-Type': 'application/octet-stream',
            'x-amz-storage-class': 'INTELLIGENT_TIERING',
            'tagging': tagging_xml,
        },
        Conditions=[
            {'Content-Type': 'application/octet-stream'},
            {'x-amz-storage-class': 'INTELLIGENT_TIERING'},
            {'tagging': tagging_xml},
        ],
        ExpiresIn=60,
    )

    form_fields = presigned['fields'].copy()
    try:
        with open(tmp_file_path, 'rb') as upload_fp:
            files = {'file': (key, upload_fp, 'application/octet-stream')}
            resp = requests.post(
                presigned['url'], data=form_fields, files=files, timeout=30, verify=False
            )
    finally:
        os.unlink(tmp_file_path)

    assert resp.status_code in (200, 201, 204)
    actual_etag = resp.headers.get('ETag')
    assert actual_etag == expected_etag

    head = s3_client.head_object(Bucket=bucket_name, Key=key)
    assert head['ETag'] == expected_etag
    assert head.get('StorageClass') == 'INTELLIGENT_TIERING'

    tagging = s3_client.get_object_tagging(Bucket=bucket_name, Key=key)
    tags = tagging.get('TagSet', [])
    assert len(tags) == 1
    assert tags[0]['Key'] == 'Tag Name'
    assert tags[0]['Value'] == 'Tag Value'
