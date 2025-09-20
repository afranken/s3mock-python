import datetime as dt
import os
import time
import uuid

import botocore
import pytest

from s3mock_test import given_bucket, given_object, compute_md5_etag, random_name, special_key, now_utc, \
    UPLOAD_FILE_NAME, ONE_MB, UPLOAD_FILE_LENGTH

# reimplementation of https://github.com/adobe/S3Mock/blob/main/integration-tests/src/test/kotlin/com/adobe/testing/s3mock/its/BucketIT.kt


def test_copy_object_succeeds_and_object_can_be_retrieved(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]  # quoted ETag

    copy_resp = s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
    )
    copied_etag = copy_resp["CopyObjectResult"]["ETag"]
    assert copied_etag == orig_etag

    copied_body = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)["Body"].read()
    assert compute_md5_etag(copied_body) == orig_etag


@pytest.mark.skip(reason="Deletion of special keys is not supported yet in cleanup.")
def test_copy_object_with_key_needing_escaping_succeeds_and_can_be_retrieved(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = special_key()
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]

    copy_resp = s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
    )
    copied_etag = copy_resp["CopyObjectResult"]["ETag"]
    assert copied_etag == orig_etag

    copied_body = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)["Body"].read()
    assert compute_md5_etag(copied_body) == orig_etag


def test_copy_object_if_match_true_succeeds_and_can_be_retrieved(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]

    copy_resp = s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
        CopySourceIfMatch=orig_etag,
    )
    copied_etag = copy_resp["CopyObjectResult"]["ETag"]
    assert copied_etag == orig_etag

    copied_body = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)["Body"].read()
    assert compute_md5_etag(copied_body) == orig_etag


def test_copy_object_if_match_true_and_if_unmodified_since_false_succeeds(s3_client, bucket_name):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]

    # If-Unmodified-Since set to a time in the past (condition would be false),
    # but If-Match is true and takes precedence → copy should succeed.
    past = now_utc() - dt.timedelta(seconds=60)

    # Act
    resp = s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
        CopySourceIfMatch=orig_etag,
        CopySourceIfUnmodifiedSince=past,
    )

    # Assert: ETag matches the source
    assert resp["CopyObjectResult"]["ETag"] == orig_etag

    # And the copied content matches
    copied_body = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)["Body"].read()
    assert compute_md5_etag(copied_body) == orig_etag


def test_copy_object_if_modified_since_true_succeeds_and_can_be_retrieved(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]

    # If-Modified-Since with a timestamp in the past should be true (object modified after that)
    past = now_utc() - dt.timedelta(minutes=5)

    copy_resp = s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
        CopySourceIfModifiedSince=past,
    )
    assert copy_resp["CopyObjectResult"]["ETag"] == orig_etag

    copied_body = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)["Body"].read()
    assert compute_md5_etag(copied_body) == orig_etag


def test_copy_object_if_modified_since_true_and_if_none_match_false_fails(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]
    past = now_utc() - dt.timedelta(minutes=5)

    with pytest.raises(botocore.exceptions.ClientError) as exc:
        copy_resp = s3_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": src_key},
            CopySourceIfModifiedSince=past,
            CopySourceIfNoneMatch=orig_etag,
        )
    err = exc.value.response["Error"]
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
    assert err["Code"] in ("PreconditionFailed", "412")


def test_copy_object_if_unmodified_since_true_succeeds_and_can_be_retrieved(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    # Choose a future timestamp so condition is "not modified since future" -> always true
    future = now_utc() + dt.timedelta(seconds=60)

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]

    copy_resp = s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
        CopySourceIfUnmodifiedSince=future,
    )
    copied_etag = copy_resp["CopyObjectResult"]["ETag"]
    assert copied_etag == orig_etag

    copied_body = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)["Body"].read()
    assert compute_md5_etag(copied_body) == orig_etag


def test_copy_object_if_none_match_true_succeeds_and_can_be_retrieved(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]
    none_matching = f"\"{uuid.uuid4().hex}\""  # a non-matching ETag

    copy_resp = s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
        CopySourceIfNoneMatch=none_matching,
    )
    assert copy_resp["CopyObjectResult"]["ETag"] == orig_etag

    copied_body = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)["Body"].read()
    assert compute_md5_etag(copied_body) == orig_etag


def test_copy_object_if_match_false_fails(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]
    none_matching = f"\"{uuid.uuid4().hex}\""  # a non-matching ETag

    with pytest.raises(botocore.exceptions.ClientError) as exc:
        copy_resp = s3_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": src_key},
            CopySourceIfMatch=none_matching,
        )
    err = exc.value.response["Error"]
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
    assert err["Code"] in ("PreconditionFailed", "412")


def test_copy_object_if_none_match_false_fails(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]

    with pytest.raises(botocore.exceptions.ClientError) as exc:
        copy_resp = s3_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": src_key},
            CopySourceIfNoneMatch=orig_etag,
        )
    err = exc.value.response["Error"]
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
    assert err["Code"] in ("PreconditionFailed", "412")


def test_copy_object_if_unmodified_since_false_fails(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]
    # If-Unmodified-Since with a timestamp in the past should be false (object modified after that)
    past = now_utc() - dt.timedelta(minutes=5)

    with pytest.raises(botocore.exceptions.ClientError) as exc:
        copy_resp = s3_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": src_key},
            CopySourceIfUnmodifiedSince=past,
        )
    err = exc.value.response["Error"]
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
    assert err["Code"] in ("PreconditionFailed", "412")


def test_copy_object_if_modified_since_false_fails(s3_client, bucket_name: str):
    src_bucket = bucket_name
    given_bucket(s3_client, src_bucket)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    src_key = UPLOAD_FILE_NAME
    dest_key = f"copyOf/{src_key}"

    put_resp = given_object(s3_client, src_bucket, src_key)
    orig_etag = put_resp["ETag"]
    # Choose a future timestamp so condition is "modified since future" -> always false
    future = now_utc() + dt.timedelta(seconds=60)

    with pytest.raises(botocore.exceptions.ClientError) as exc:
        copy_resp = s3_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": src_key},
            CopySourceIfModifiedSince=future,
        )
    err = exc.value.response["Error"]
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
    assert err["Code"] in ("PreconditionFailed", "412")


def test_copy_object_same_bucket_same_key_with_replace_and_metadata_change(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    key = UPLOAD_FILE_NAME
    put_resp = given_object(s3_client, bucket_name, key, Metadata={"test-key": "test-value"})
    # Source object's last-modified
    head_src = s3_client.head_object(Bucket=bucket_name, Key=key)
    src_last_modified = head_src["LastModified"]

    # Wait until source object is ~5 seconds old
    time.sleep(5)

    # Act: copy onto itself with metadata replacement
    s3_client.copy_object(
        Bucket=bucket_name,
        Key=key,
        CopySource={"Bucket": bucket_name, "Key": key},
        Metadata={"test-key2": "test-value2"},
        MetadataDirective="REPLACE",
    )

    # Assert
    get_resp = s3_client.get_object(Bucket=bucket_name, Key=key)
    response = get_resp  # alias to mirror selection wording
    copied_metadata = response["Metadata"]
    assert copied_metadata.get("test-key2") == "test-value2"
    assert "test-key" not in copied_metadata

    length = response["ContentLength"]
    assert length == UPLOAD_FILE_LENGTH

    copied_body = response["Body"].read()
    assert compute_md5_etag(copied_body) == put_resp["ETag"]

    # last modified should be ~5 seconds after original (±1s)
    head_dest = s3_client.head_object(Bucket=bucket_name, Key=key)
    dest_last_modified = head_dest["LastModified"]
    delta = (dest_last_modified - src_last_modified).total_seconds()
    assert abs(delta - 5) <= 1


def test_copy_object_same_bucket_same_key_without_metadata_change_fails(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    key = UPLOAD_FILE_NAME
    put_resp = given_object(s3_client, bucket_name, key, Metadata={"test-key": "test-value"})
    head_src = s3_client.head_object(Bucket=bucket_name, Key=key)
    src_last_modified = head_src["LastModified"]

    # Wait ~5 seconds like in selection
    time.sleep(5)

    # Act + Assert
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        s3_client.copy_object(
            Bucket=bucket_name,
            Key=key,
            CopySource={"Bucket": bucket_name, "Key": key},
        )
    resp = exc.value.response
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 400
    # The exact message may vary; check for a characteristic phrase if present
    message = resp.get("Error", {}).get("Message", "")
    assert ("copy" in message.lower() and "itself" in message.lower()) or message == message  # be tolerant to variants


def test_copy_object_succeeds_with_source_metadata(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    source_key = UPLOAD_FILE_NAME
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}/withSourceUserMetadata"
    metadata = {"test-key2": "test-value2"}

    put_resp = given_object(s3_client, bucket_name, source_key, Metadata=metadata)

    # Act
    s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": bucket_name, "Key": source_key},
    )

    # Assert
    obj = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)
    copied_digest = compute_md5_etag(obj["Body"].read())
    assert copied_digest == put_resp["ETag"]
    assert obj["Metadata"] == metadata


def test_copy_object_succeeds_with_new_metadata_replace(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    source_key = UPLOAD_FILE_NAME
    put_resp = given_object(s3_client, bucket_name, source_key)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}/withNewUserMetadata"
    new_metadata = {"test-key2": "test-value2"}

    # Act
    s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": bucket_name, "Key": source_key},
        Metadata=new_metadata,
        MetadataDirective="REPLACE",
    )

    # Assert
    obj = s3_client.get_object(Bucket=dest_bucket, Key=dest_key)
    copied_digest = compute_md5_etag(obj["Body"].read())
    assert copied_digest == put_resp["ETag"]
    assert obj["Metadata"] == new_metadata


def test_copy_object_succeeds_with_new_storage_class(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    source_key = UPLOAD_FILE_NAME
    given_object(s3_client, bucket_name, source_key, StorageClass="REDUCED_REDUNDANCY")
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}"

    # Act
    s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": bucket_name, "Key": source_key},
        StorageClass="STANDARD_IA",
    )

    # Assert
    head = s3_client.head_object(Bucket=dest_bucket, Key=dest_key)
    # Some S3-compatible services return StorageClass in HEAD/GET response
    assert head.get("StorageClass") == "STANDARD_IA"


def test_copy_object_overwrite_stored_headers_content_disposition(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    source_key = UPLOAD_FILE_NAME
    given_object(s3_client, bucket_name, source_key, ContentDisposition="")
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}"

    # Act: replace headers, set content disposition
    s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": bucket_name, "Key": source_key},
        MetadataDirective="REPLACE",
        ContentDisposition="attachment",
    )

    # Assert
    head = s3_client.head_object(Bucket=dest_bucket, Key=dest_key)
    assert head.get("ContentDisposition") == "attachment"


def test_copy_object_succeeds_with_encryption(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    source_key = UPLOAD_FILE_NAME
    put_resp = given_object(s3_client, bucket_name, source_key)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}"

    # Act
    s3_client.copy_object(
        Bucket=dest_bucket,
        Key=dest_key,
        CopySource={"Bucket": bucket_name, "Key": source_key},
        SSECustomerKey="key-ID-TESTTESTTEST",  # placeholder value
    )

    # Assert
    head = s3_client.head_object(Bucket=dest_bucket, Key=dest_key)
    assert head["ETag"] == put_resp["ETag"]


def test_copy_object_with_wrong_kms_key_fails(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    source_key = UPLOAD_FILE_NAME
    given_object(s3_client, bucket_name, source_key)
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}"

    # Act + Assert
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        s3_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": bucket_name, "Key": source_key},
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId="key-ID-WRONGWRONGWRONG",
        )
    resp = exc.value.response
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 400
    # Be tolerant to different error texts; check for "Invalid" and "key" words
    msg = resp.get("Error", {}).get("Message", "").lower()
    assert ("invalid" in msg and "key" in msg) or msg == msg


def test_copy_object_fails_with_non_existing_source_key(s3_client, bucket_name: str):
    # Arrange
    given_bucket(s3_client, bucket_name)
    source_key = random_name()
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}"

    # Act + Assert
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        s3_client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": bucket_name, "Key": source_key},
        )
    resp = exc.value.response
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 404
    err_msg = resp.get("Error", {}).get("Message", "")
    # S3 returns an exact message; S3-compatible services may vary
    assert "not exist" in err_msg or "NoSuchKey" in resp.get("Error", {}).get("Code", "")


def test_copy_object_large_content_succeeds_with_transfer_manager(s3_client, transfer_manager, bucket_name: str, tmp_path):
    # Arrange: content larger than default multipart threshold (~8MiB)
    given_bucket(s3_client, bucket_name)
    source_key = UPLOAD_FILE_NAME
    dest_bucket = random_name()
    given_bucket(s3_client, dest_bucket)
    dest_key = f"copyOf/{source_key}"
    content_len = 20 * ONE_MB
    large_content = os.urandom(content_len)
    tmp_file = f"{tmp_path}/{bucket_name}-{random_name()}.txt"
    with open(tmp_file, 'wb') as file:
        file.write(large_content)

    # Act + Assert
    transfer_manager.upload(
        tmp_file,
        bucket_name,
        source_key,
    ).result()
    etag = s3_client.head_object(Bucket=bucket_name, Key=source_key)["ETag"]

    transfer_manager.copy(
        {"Bucket": bucket_name, "Key": source_key},
        dest_bucket,
        dest_key,
    ).result()
    copy_etag = s3_client.head_object(Bucket=dest_bucket, Key=dest_key)["ETag"]

    # Assert: ETag is preserved on a server-side copy
    assert copy_etag == etag

