import json

from image_poc.s3_store import S3Store


class FakeS3Client:
    def __init__(self):
        self.puts = []

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        return {"ResponseMetadata": {"RequestId": "s3-request"}}

    def generate_presigned_url(self, ClientMethod, Params, ExpiresIn):
        assert ClientMethod == "get_object"
        return f"https://signed.example/{Params['Bucket']}/{Params['Key']}?expires={ExpiresIn}"


def test_write_image_stores_png_under_prefix():
    client = FakeS3Client()
    store = S3Store("bucket", "phase3", client=client)

    artifact = store.write_image(b"png-bytes")

    assert artifact.artifact_id
    assert artifact.s3_uri == f"s3://bucket/phase3/images/{artifact.artifact_id}.png"
    assert artifact.artifact_url.startswith("https://signed.example/")
    assert client.puts[0]["ContentType"] == "image/png"
    assert client.puts[0]["ServerSideEncryption"] == "AES256"


def test_record_audit_writes_json_without_token_material():
    client = FakeS3Client()
    store = S3Store("bucket", "phase3", client=client)

    audit_id = store.record_audit({"tool_name": "generate_image", "result_status": "success"})

    body = json.loads(client.puts[0]["Body"].decode("utf-8"))
    assert audit_id.audit_id == body["audit_id"]
    assert audit_id.s3_uri.startswith("s3://bucket/phase3/audit/")
    assert body["tool_name"] == "generate_image"
    assert "token" not in json.dumps(body).lower()
    assert client.puts[0]["ContentType"] == "application/json"
