from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import boto3


@dataclass(frozen=True)
class S3Artifact:
    artifact_id: str
    s3_uri: str
    artifact_url: str
    expires_in: int


@dataclass(frozen=True)
class S3AuditRecord:
    audit_id: str
    s3_uri: str


class S3Store:
    def __init__(
        self,
        bucket: str,
        prefix: str,
        client: Any | None = None,
        presign_expires: int = 900,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.client = client or boto3.client("s3")
        self.presign_expires = presign_expires

    def write_image(self, image_bytes: bytes) -> S3Artifact:
        artifact_id = uuid.uuid4().hex
        key = self._key("images", f"{artifact_id}.png")
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=image_bytes,
            ContentType="image/png",
            ServerSideEncryption="AES256",
        )
        artifact_url = self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=self.presign_expires,
        )
        return S3Artifact(
            artifact_id=artifact_id,
            s3_uri=f"s3://{self.bucket}/{key}",
            artifact_url=artifact_url,
            expires_in=self.presign_expires,
        )

    def record_audit(self, event: dict[str, Any]) -> S3AuditRecord:
        audit_id = uuid.uuid4().hex
        recorded_at = datetime.now(timezone.utc)
        record = {
            "audit_id": audit_id,
            "recorded_at": recorded_at.isoformat(),
            **event,
        }
        key = self._key("audit", f"{recorded_at.date().isoformat()}/{audit_id}.json")
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(record, sort_keys=True).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        return S3AuditRecord(audit_id=audit_id, s3_uri=f"s3://{self.bucket}/{key}")

    def _key(self, category: str, name: str) -> str:
        parts = [part for part in (self.prefix, category, name) if part]
        return "/".join(parts)
