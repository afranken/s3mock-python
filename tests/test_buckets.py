
def test_create_list_delete_bucket(s3_client, bucket_name: str):
    buckets = s3_client.list_buckets()
    assert len(buckets['Buckets']) == 0

    s3_client.create_bucket(Bucket=bucket_name)
    response = s3_client.list_buckets()
    assert len(response['Buckets']) == 1
    assert response['Buckets'][0]['Name'] == bucket_name

    s3_client.delete_bucket(Bucket=bucket_name)
    buckets = s3_client.list_buckets()
    assert len(buckets['Buckets']) == 0
