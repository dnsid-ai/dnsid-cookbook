from __future__ import annotations

import time
from typing import Any


class ReplayError(RuntimeError):
    pass


class MemoryReplayStore:
    def __init__(self) -> None:
        self.seen: dict[str, float] = {}

    def reserve(self, nonce: str, ttl: int, now: float) -> None:
        self.seen = {key: expiry for key, expiry in self.seen.items() if expiry > now}
        if nonce in self.seen:
            raise ReplayError("action proof was replayed")
        self.seen[nonce] = now + ttl


class DynamoReplayStore:
    def __init__(self, table_name: str) -> None:
        import boto3

        self.table: Any = boto3.resource("dynamodb").Table(table_name)

    def reserve(self, nonce: str, ttl: int, now: float | None = None) -> None:
        from botocore.exceptions import ClientError

        now = time.time() if now is None else now
        try:
            self.table.put_item(
                Item={"nonce": nonce, "expires_at": int(now + ttl)},
                ConditionExpression="attribute_not_exists(nonce)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise ReplayError("action proof was replayed") from exc
            raise ReplayError("replay store unavailable") from exc
