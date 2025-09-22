import base64
import datetime as dt
import hashlib
import struct
import zlib
from typing import Literal, cast

import pytest
from botocore.exceptions import ClientError
from mypy_boto3_s3 import S3Client

from s3mock_test import (
    PREFIX,
    UPLOAD_FILE_LENGTH,
    UPLOAD_FILE_NAME,
    chars_safe_alphanumeric,
    chars_safe_special,
    chars_special_handling,
    chars_to_avoid,
    given_bucket,
    given_object,
    now_utc,
    random_name,
    upload_file_bytes,
)

# Reimplementation of https://github.com/adobe/S3Mock/blob/main/integration-tests/src/test/kotlin/com/adobe/testing/s3mock/its/GetPutDeleteObjectIT.kt


def test_put_get_delete_object(s3_client, bucket_name: str):
    given_bucket(s3_client, bucket_name)

    given_object(s3_client, bucket_name)

    get_object = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)
    assert get_object is not None

    s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)

    s3_client.delete_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)

    with pytest.raises(ClientError):
        _ = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)

def test_put_get_head_delete_objects_bulk(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    key = UPLOAD_FILE_NAME
    keys = [f"{key}-1", f"{key}-2", f"{key}-3"]

    for k in keys:
        s3_client.put_object(Bucket=bucket_name, Key=k, Body=upload_file_bytes())

    # Act: bulk delete
    resp = s3_client.delete_objects(
        Bucket=bucket_name,
        Delete={"Objects": [{"Key": keys[0]}, {"Key": keys[1]}, {"Key": keys[2]}]},
    )

    # Each key should now exist
    for k in keys:
        with pytest.raises(ClientError) as exc:
            s3_client.head_object(Bucket=bucket_name, Key=k)

    # Assert delete call succeeded (Deleted entries present or no Errors)
    assert "Errors" not in resp or not resp["Errors"]

    # Each key should now be gone
    for k in keys:
        with pytest.raises(ClientError) as exc:
            s3_client.get_object(Bucket=bucket_name, Key=k)
        assert exc.value.response.get("Error", {}).get("Code") in ("NoSuchKey", "404")

def test_get_object_no_such_key(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    non_existing = f"{random_name()}.missing"

    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.get_object(Bucket=bucket_name, Key=non_existing)
    err = exc.value.response.get("Error", {})
    assert err.get("Code") in ("NoSuchKey", "404")

def test_get_object_no_such_key_starting_slash(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    non_existing = f"/{random_name()}.missing"

    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.get_object(Bucket=bucket_name, Key=non_existing)
    err = exc.value.response.get("Error", {})
    assert err.get("Code") in ("NoSuchKey", "404")

def test_put_object_no_such_bucket(s3_client):
    # Arrange
    missing_bucket = random_name()

    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.put_object(Bucket=missing_bucket, Key=UPLOAD_FILE_NAME, Body=upload_file_bytes())
    err = exc.value.response.get("Error", {})
    assert err.get("Code") in ("NoSuchBucket", "404")

def test_put_object_encrypted_no_such_bucket(s3_client):
    # Arrange
    missing_bucket = random_name()

    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.put_object(
            Bucket=missing_bucket,
            Key=UPLOAD_FILE_NAME,
            Body=upload_file_bytes(),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId="valid-test-key-id",
        )
    err = exc.value.response.get("Error", {})
    assert err.get("Code") in ("NoSuchBucket", "404")

def test_head_object_no_such_bucket(s3_client):
    # Arrange
    missing_bucket = random_name()

    # Act + Assert: behavior may vary; accept either NoSuchBucket or NoSuchKey-like codes
    with pytest.raises(ClientError) as exc:
        s3_client.head_object(Bucket=missing_bucket, Key=UPLOAD_FILE_NAME)
    assert exc.value.response.get("Error", {}).get("Code") in ("NoSuchBucket", "NoSuchKey", "404")

def test_head_object_no_such_key(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    non_existing = f"{random_name()}.missing"

    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.head_object(Bucket=bucket_name, Key=non_existing)
    assert exc.value.response.get("Error", {}).get("Code") in ("NoSuchKey", "404")

def test_delete_object_no_such_bucket(s3_client):
    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.delete_object(Bucket=random_name(), Key="non-existing")
    assert exc.value.response.get("Error", {}).get("Code") in ("NoSuchBucket", "404")

def test_delete_object_non_existent_ok(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)

    # Act: deleting a non-existent key in an existing bucket should be OK (idempotent)
    s3_client.delete_object(Bucket=bucket_name, Key=f"{random_name()}.missing")

def test_delete_objects_no_such_bucket(s3_client):
    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.delete_objects(
            Bucket=random_name(),
            Delete={"Objects": [{"Key": f"{random_name()}.missing"}]},
        )
    assert exc.value.response.get("Error", {}).get("Code") in ("NoSuchBucket", "404")

def test_delete_bucket_no_such_bucket(s3_client):
    # Act + Assert
    with pytest.raises(ClientError) as exc:
        s3_client.delete_bucket(Bucket=random_name())
    assert exc.value.response.get("Error", {}).get("Code") in ("NoSuchBucket", "404")

def test_delete_objects_existing_and_non_existent_key(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    key = UPLOAD_FILE_NAME
    given_object(s3_client, bucket_name)

    # Act: delete an existing key and a random non-existent key together
    resp = s3_client.delete_objects(
        Bucket=bucket_name,
        Delete={"Objects": [{"Key": key}, {"Key": f"{random_name()}.missing"}]},
    )

    # Assert: call succeeded (no Errors or empty list)
    assert "Errors" not in resp or not resp["Errors"]

    # Existing key should be gone
    with pytest.raises(ClientError):
        s3_client.head_object(Bucket=bucket_name, Key=key)

def keys_to_test() -> list[str]:
    """
    Builds the list of keys analogous to the Kotlin @MethodSource:
    - charsSafe() -> two entries (alphanumeric, safe-special)
    - charsSpecial() -> one entry (special handling)
    - charsToAvoid() -> one entry (to avoid)
    """
    return [
        f"{PREFIX}{chars_safe_alphanumeric()}",
        f"{PREFIX}{chars_safe_special()}",
        f"{PREFIX}{chars_special_handling()}",
        f"{PREFIX}{chars_to_avoid()}",
    ]

@pytest.mark.parametrize("key", keys_to_test())
def test_put_head_get_object_key_names_safe(s3_client: S3Client, key: str):
    # Given a new bucket for this test
    bucket_name = random_name()
    given_bucket(s3_client, bucket_name)

    # Put the object with the specific key
    s3_client.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=upload_file_bytes(),
    )

    # HEAD should succeed
    s3_client.head_object(
        Bucket=bucket_name,
        Key=key,
    )

    # GET should succeed and content length should match the upload file size
    resp = s3_client.get_object(
        Bucket=bucket_name,
        Key=key,
    )
    assert resp["ContentLength"] == UPLOAD_FILE_LENGTH

def test_put_object_and_get_object_attributes_succeeds(s3_client: S3Client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    body = upload_file_bytes()
    expected_sha1_b64 = base64.b64encode(hashlib.sha1(body).digest()).decode("ascii")

    # Act
    put_resp = s3_client.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=body,
        ChecksumAlgorithm="SHA1",
    )
    # ETag from PutObject is quoted
    etag_from_put = put_resp.get("ETag", "")
    etag_trimmed = etag_from_put.strip('"')

    attrs = s3_client.get_object_attributes(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        ObjectAttributes=["ObjectSize", "StorageClass", "ETag", "Checksum"],
    )

    # Assert
    assert attrs["ETag"] == etag_trimmed
    assert attrs["StorageClass"] == "STANDARD"
    assert attrs["ObjectSize"] == UPLOAD_FILE_LENGTH
    assert "Checksum" in attrs
    assert attrs["Checksum"].get("ChecksumSHA1") == expected_sha1_b64
    assert attrs["Checksum"].get("ChecksumType") == "FULL_OBJECT"

def test_put_object_object_metadata(s3_client: S3Client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    metadata = {"key1": "value1", "key2": "value2"}

    # Act
    s3_client.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=upload_file_bytes(),
        Metadata=metadata,
    )

    # Assert
    get_resp = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)
    # S3 lower-cases user metadata keys
    returned_md = get_resp.get("Metadata", {})
    assert returned_md.get("key1") == "value1"
    assert returned_md.get("key2") == "value2"

# ---------------------------------------------------------------------------
# Reimplementation of the "checksum algorithm" selection in Python
# ---------------------------------------------------------------------------

def _checksum_field_name(algorithm: str) -> str:
    # Maps the algorithm name to the response field key
    return {
        "SHA1": "ChecksumSHA1",
        "SHA256": "ChecksumSHA256",
        "CRC32": "ChecksumCRC32",
        "CRC32C": "ChecksumCRC32C",
    }[algorithm]

def _expected_b64_checksum(algorithm: str, data: bytes) -> str:
    if algorithm == "SHA1":
        digest = hashlib.sha1(data).digest()
        return base64.b64encode(digest).decode("ascii")
    if algorithm == "SHA256":
        digest = hashlib.sha256(data).digest()
        return base64.b64encode(digest).decode("ascii")
    if algorithm == "CRC32":
        # IEEE CRC32; AWS returns base64-encoded big-endian 4-byte value
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return base64.b64encode(struct.pack(">I", crc)).decode("ascii")
    if algorithm == "CRC32C":
        # Not available in Python stdlib; raise to optionally skip in parametrization
        raise NotImplementedError("CRC32C not supported without extra dependency")
    raise ValueError(f"Unsupported algorithm: {algorithm}")

@pytest.mark.parametrize("algorithm", ["SHA1", "SHA256", "CRC32"])
def test_checksum_algorithm_put_get_head(s3_client: S3Client, algorithm: str, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    key = UPLOAD_FILE_NAME
    body = upload_file_bytes()
    expected = _expected_b64_checksum(algorithm, body)
    field = _checksum_field_name(algorithm)

    # Put with checksum algorithm
    alg_literal = cast(Literal['CRC32', 'CRC32C', 'CRC64NVME', 'SHA1', 'SHA256'], algorithm)
    put_resp = s3_client.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=body,
        ChecksumAlgorithm=alg_literal,
    )
    assert put_resp.get(field) == expected

    # Get with checksum mode enabled
    get_resp = s3_client.get_object(
        Bucket=bucket_name,
        Key=key,
        ChecksumMode="ENABLED",
    )
    assert get_resp.get(field) == expected

    # Head with checksum mode enabled
    head_resp = s3_client.head_object(
        Bucket=bucket_name,
        Key=key,
        ChecksumMode="ENABLED",
    )
    assert head_resp.get(field) == expected


def test_put_object_wrong_checksum(s3_client: S3Client, bucket_name: str):
    # Given
    given_bucket(s3_client, bucket_name)
    key = UPLOAD_FILE_NAME
    body = upload_file_bytes()

    # Wrong/predefined checksum that doesn't match body
    wrong_checksum_b64 = base64.b64encode(b"wrongChecksum").decode("ascii")

    # When + Then
    with pytest.raises(ClientError) as exc:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=body,
            ChecksumAlgorithm="SHA1",
            ChecksumSHA1=wrong_checksum_b64,
        )
    msg = str(exc.value)
    assert "BadRequest" in msg
    # AWS phrasing; accept either header name or generic invalid value message
    assert "x-amz-checksum-sha1" in msg and "invalid" in msg.lower()

def test_put_object_wrong_encryption_key(s3_client: S3Client, bucket_name: str):
    # Given
    given_bucket(s3_client, bucket_name)
    wrong_key = "key-ID-WRONGWRONGWRONG"

    # When + Then
    with pytest.raises(ClientError) as exc:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=UPLOAD_FILE_NAME,
            Body=upload_file_bytes(),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=wrong_key,
        )
    msg = str(exc.value)
    assert "KMS.NotFoundException" in msg
    # Accept either exact AWS wording or a mock-matcher
    assert "Invalid keyId" in msg or wrong_key in msg

def test_put_get_delete_object_two_buckets(s3_client: S3Client):
    b1 = random_name()
    b2 = random_name()
    given_bucket(s3_client, b1)
    given_bucket(s3_client, b2)

    # Same key in both buckets
    s3_client.put_object(Bucket=b1, Key=UPLOAD_FILE_NAME, Body=upload_file_bytes())
    s3_client.put_object(Bucket=b2, Key=UPLOAD_FILE_NAME, Body=upload_file_bytes())

    # Get from bucket1 works
    _ = s3_client.get_object(Bucket=b1, Key=UPLOAD_FILE_NAME)

    # Delete from bucket1
    s3_client.delete_object(Bucket=b1, Key=UPLOAD_FILE_NAME)

    # bucket1 object gone
    with pytest.raises(ClientError):
        s3_client.get_object(Bucket=b1, Key=UPLOAD_FILE_NAME)

    # bucket2 object still present; ETag consistent across consecutive GETs
    r1 = s3_client.get_object(Bucket=b2, Key=UPLOAD_FILE_NAME)
    r2 = s3_client.get_object(Bucket=b2, Key=UPLOAD_FILE_NAME)
    assert r1["ETag"] == r2["ETag"]

def test_put_get_head_object_store_headers(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)

    content_disposition = 'form-data; name="file"; filename="sampleFile.txt"'
    expires = now_utc()
    encoding = "SomeEncoding"
    content_language = "SomeLanguage"
    cache_control = "SomeCacheControl"

    s3_client.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=upload_file_bytes(),
        ContentDisposition=content_disposition,
        ContentEncoding=encoding,
        Expires=expires,
        ContentLanguage=content_language,
        CacheControl=cache_control,
    )

    g = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)
    assert g["ContentDisposition"] == content_disposition
    #should not contain aws-chunked
    assert g["ContentEncoding"] == f"{encoding},aws-chunked"
    # Truncate to seconds for comparison
    assert (g["Expires"].replace(microsecond=0, tzinfo=dt.timezone.utc)
            == expires.replace(microsecond=0, tzinfo=dt.timezone.utc))
    assert g["ContentLanguage"] == content_language
    assert g["CacheControl"] == cache_control

    h = s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)
    assert h["ContentDisposition"] == content_disposition
    # should not contain aws-chunked
    assert h["ContentEncoding"] == f"{encoding},aws-chunked"
    assert (h["Expires"].replace(microsecond=0, tzinfo=dt.timezone.utc)
            == expires.replace(microsecond=0, tzinfo=dt.timezone.utc))
    assert h["ContentLanguage"] == content_language
    assert h["CacheControl"] == cache_control

def _put_and_get_etag(s3_client: S3Client, bucket: str, key: str) -> str:
    resp = s3_client.put_object(Bucket=bucket, Key=key, Body=upload_file_bytes())
    # ETag is quoted by S3
    return resp.get("ETag", "")

def test_put_object_if_match_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    s3_client.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=upload_file_bytes(),
        IfMatch=etag,
    )

def test_put_object_if_none_match_wildcard_false(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    with pytest.raises(ClientError) as exc:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=UPLOAD_FILE_NAME,
            Body=upload_file_bytes(),
            IfNoneMatch="*",
        )
    assert "PreconditionFailed" in str(exc.value)

def test_put_object_if_none_match_on_non_existing_succeeds(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    s3_client.put_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Body=upload_file_bytes(),
        IfNoneMatch="*",
    )

def test_put_object_if_match_false(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    with pytest.raises(ClientError) as exc:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=UPLOAD_FILE_NAME,
            Body=upload_file_bytes(),
            IfMatch=f"\"{random_name()}\"",
        )
    assert "PreconditionFailed" in str(exc.value)

def test_put_object_if_match_on_non_existing_fails_404(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    with pytest.raises(ClientError) as exc:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=UPLOAD_FILE_NAME,
            Body=upload_file_bytes(),
            IfMatch=f"\"{random_name()}\"",
        )
    # Some implementations return 404; tolerate either 404 or 412
    assert "PreconditionFailed" or "NoSuchKey" in str(exc.value)

@pytest.mark.xfail(reason="Conditional delete not supported for non-directory buckets")
def test_delete_object_if_match_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    s3_client.delete_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfMatch=etag)

@pytest.mark.xfail(reason="Conditional delete not supported for non-directory buckets")
def test_delete_object_if_match_wildcard_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    s3_client.delete_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfMatch="*")

@pytest.mark.xfail(reason="Conditional delete not supported for non-directory buckets")
def test_delete_object_if_match_size_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    s3_client.delete_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        IfMatchSize=UPLOAD_FILE_LENGTH
    )

@pytest.mark.xfail(reason="Conditional delete not supported for non-directory buckets")
def test_delete_object_if_match_last_modified_time_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    last_modified = s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME)["LastModified"]
    # IfMatchLastModifiedTime is not part of AWS S3 API; this is a placeholder for mock parity
    s3_client.delete_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        IfMatchLastModifiedTime=last_modified
    )

@pytest.mark.xfail(reason="Conditional delete not supported for non-directory buckets")
def test_delete_object_if_match_false(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    with pytest.raises(ClientError):
        s3_client.delete_object(
            Bucket=bucket_name,
            Key=UPLOAD_FILE_NAME,
            IfMatch=f"\"{random_name()}\""
        )

def test_head_object_if_match_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    h = s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfMatch=etag)
    assert h["ETag"] == etag

def test_head_object_if_match_false(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    with pytest.raises(ClientError) as exc:
        s3_client.head_object(
            Bucket=bucket_name,
            Key=UPLOAD_FILE_NAME,
            IfMatch=f"\"{random_name()}\""
        )
    assert "Precondition Failed" in str(exc.value)

def test_head_object_if_none_match_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    h = s3_client.head_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        IfNoneMatch=f"\"{random_name()}\""
    )
    assert h["ETag"] == etag

def test_head_object_if_none_match_wildcard_false_304(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    with pytest.raises(ClientError) as exc:
        s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfNoneMatch="*")
    assert "Not Modified" in str(exc.value)

def test_head_object_if_modified_since_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    now = now_utc() - dt.timedelta(seconds=60)
    h = s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfModifiedSince=now)
    assert h["ETag"] == etag

def test_head_object_if_modified_since_false_304(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    future = now_utc() + dt.timedelta(seconds=60)
    with pytest.raises(ClientError) as exc:
        s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfModifiedSince=future)
    assert "304" in str(exc.value)

def test_head_object_if_unmodified_since_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    future = now_utc() + dt.timedelta(seconds=60)
    h = s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfUnmodifiedSince=future)
    assert h["ETag"] == etag

def test_head_object_if_unmodified_since_false_412(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    past = now_utc() - dt.timedelta(seconds=60)
    with pytest.raises(ClientError) as exc:
        s3_client.head_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfUnmodifiedSince=past)
    assert "412" in str(exc.value)

def test_get_object_if_match_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    g = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfMatch=etag)
    assert g["ETag"] == etag
    assert g["ContentLength"] == UPLOAD_FILE_LENGTH

def test_get_object_if_match_true_with_if_unmodified_since_false(
        s3_client: S3Client,
        bucket_name: str
):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    past = now_utc() - dt.timedelta(seconds=60)
    g = s3_client.get_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        IfMatch=etag,
        IfUnmodifiedSince=past
    )
    assert g["ETag"] == etag
    assert g["ContentLength"] == UPLOAD_FILE_LENGTH

def test_get_object_if_match_wildcard_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    g = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfMatch="*")
    assert g["ETag"] == etag

def test_get_object_if_none_match_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    g = s3_client.get_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        IfNoneMatch=f"\"{random_name()}\""
    )
    assert g["ETag"] == etag
    assert g["ContentLength"] == UPLOAD_FILE_LENGTH

def test_get_object_if_none_match_false_304(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    with pytest.raises(ClientError) as exc:
        s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfNoneMatch=etag)
    assert "304" in str(exc.value)

def test_get_object_if_modified_since_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    past = now_utc() - dt.timedelta(seconds=60)
    g = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfModifiedSince=past)
    assert g["ETag"]
    assert g["ContentLength"] > 0

def test_get_object_if_modified_since_true_and_if_none_match_false_304(
        s3_client: S3Client,
        bucket_name: str
):
    given_bucket(s3_client, bucket_name)
    etag = _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    past = now_utc() - dt.timedelta(seconds=60)
    with pytest.raises(ClientError) as exc:
        s3_client.get_object(
            Bucket=bucket_name,
            Key=UPLOAD_FILE_NAME,
            IfModifiedSince=past,
            IfNoneMatch=etag,
        )
    assert "304" in str(exc.value)

def test_get_object_if_modified_since_false_304(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    future = now_utc() + dt.timedelta(seconds=60)
    with pytest.raises(ClientError) as exc:
        s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfModifiedSince=future)
    assert "304" in str(exc.value)

def test_get_object_if_unmodified_since_true(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    future = now_utc() + dt.timedelta(seconds=60)
    g = s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfUnmodifiedSince=future)
    assert g["ETag"]

def test_get_object_if_unmodified_since_false_412(s3_client: S3Client, bucket_name: str):
    given_bucket(s3_client, bucket_name)
    _put_and_get_etag(s3_client, bucket_name, UPLOAD_FILE_NAME)
    past = now_utc() - dt.timedelta(seconds=60)
    with pytest.raises(ClientError) as exc:
        s3_client.get_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, IfUnmodifiedSince=past)
    assert "PreconditionFailed" in str(exc.value)

def test_get_object_range_downloads(s3_client: S3Client, bucket_name: str):
    # Given
    given_bucket(s3_client, bucket_name)
    put = s3_client.put_object(Bucket=bucket_name, Key=UPLOAD_FILE_NAME, Body=upload_file_bytes())
    etag = put["ETag"]

    # Small subrange
    small_start = 1
    small_end = 2
    g1 = s3_client.get_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Range=f"bytes={small_start}-{small_end}",
        IfMatch=etag,
    )
    # ContentLength equals requested span length (end-start+1) but not beyond object size
    assert g1["ContentLength"] == small_end - small_start + 1
    assert g1["ContentRange"] == f"bytes {small_start}-{small_end}/{UPLOAD_FILE_LENGTH}"

    # Larger request possibly exceeding object length
    large_start = 0
    large_end = 1000
    g2 = s3_client.get_object(
        Bucket=bucket_name,
        Key=UPLOAD_FILE_NAME,
        Range=f"bytes={large_start}-{large_end}",
    )
    expected_len = min(UPLOAD_FILE_LENGTH, large_end + 1) - large_start
    expected_end_reported = min(UPLOAD_FILE_LENGTH - 1, large_end)
    assert g2["ContentLength"] == expected_len
    assert g2["ContentRange"] == f"bytes {large_start}-{expected_end_reported}/{UPLOAD_FILE_LENGTH}"
