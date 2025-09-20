from mypy_boto3_s3.client import S3Client
from mypy_boto3_s3.type_defs import GetObjectOutputTypeDef, PutObjectOutputTypeDef

from s3mock_test import (
    UPLOAD_FILE_NAME,
    compute_md5_etag,
    compute_sha256_checksum_b64,
    given_bucket,
)

# reimplementation of https://github.com/adobe/S3Mock/blob/main/integration-tests/src/test/kotlin/com/adobe/testing/s3mock/its/AwsChunkedEncodingIT.kt

def test_put_object_with_checksum_returns_correct_checksum_get_object_returns_checksum(
        s3_client_http: S3Client,
        bucket_name: str
) -> None:
    # Arrange
    given_bucket(s3_client_http, bucket_name)

    with open(UPLOAD_FILE_NAME, "rb") as f:
        payload = f.read()

    expected_etag = compute_md5_etag(payload)
    expected_checksum = compute_sha256_checksum_b64(payload)
    expected_length = len(payload)

    # Act - PutObject with checksum
    put_resp: PutObjectOutputTypeDef = s3_client_http.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=payload,
        ChecksumAlgorithm="SHA256",
    )

    # Assert - PutObject response checksum
    put_checksum = put_resp.get("ChecksumSHA256")
    assert put_checksum, "ChecksumSHA256 should be present on PutObject response"
    assert put_checksum == expected_checksum, "ChecksumSHA256 should match expected SHA256 (base64)"

    # Act - GetObject with checksum mode enabled
    get_resp: GetObjectOutputTypeDef = s3_client_http.get_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        ChecksumMode='ENABLED',
    )

    assert get_resp.get("ETag") == expected_etag
    assert get_resp.get("ContentLength") == expected_length
    assert get_resp.get("ChecksumSHA256") == expected_checksum
    assert get_resp.get("ContentEncoding") != 'aws-chunked'


def test_put_object_creates_correct_etag_get_object_returns_etag(
        s3_client_http: S3Client,
        bucket_name: str
) -> None:
    # Arrange
    given_bucket(s3_client_http, bucket_name)

    with open(UPLOAD_FILE_NAME, "rb") as f:
        payload = f.read()

    expected_etag = compute_md5_etag(payload)
    expected_length = len(payload)

    # Act - PutObject (no checksum, single part)
    s3_client_http.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=payload,
    )

    # Act - GetObject
    get_resp: GetObjectOutputTypeDef = s3_client_http.get_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
    )

    # Assert
    assert get_resp.get("ETag") == expected_etag
    assert get_resp.get("ContentLength") == expected_length
    assert get_resp.get("ContentEncoding") != "aws-chunked"


def test_put_object_sets_content_encoding_get_object_returns_content_encoding(
        s3_client_http: S3Client,
        bucket_name: str
) -> None:
    # Arrange
    given_bucket(s3_client_http, bucket_name)
    custom_encoding = "my-custom-encoding"

    with open(UPLOAD_FILE_NAME, "rb") as f:
        payload = f.read()

    # Act - PutObject with custom Content-Encoding
    s3_client_http.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=payload,
        ContentEncoding=custom_encoding,
    )

    # Act - GetObject
    get_resp: GetObjectOutputTypeDef = s3_client_http.get_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
    )

    # Assert - ContentEncoding is preserved
    assert get_resp.get("ContentEncoding") == custom_encoding
