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

