from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ActionPayload:
    subject: str
    audience: str
    token_jti_hash: str
    tool_name: str
    arguments_hash: str
    session_hash: str
    timestamp: int
    nonce: str


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def arguments_hash(arguments: dict[str, Any]) -> str:
    return sha256(json_bytes(arguments))


def encode_payload(payload: ActionPayload) -> bytes:
    return json_bytes(asdict(payload))


def decode_payload(value: bytes) -> ActionPayload:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("proof payload must be an object")
    payload = ActionPayload(**parsed)
    for field in ("subject", "audience", "token_jti_hash", "tool_name", "arguments_hash", "session_hash", "nonce"):
        if not isinstance(getattr(payload, field), str) or not getattr(payload, field):
            raise ValueError(f"proof payload has invalid {field}")
    if isinstance(payload.timestamp, bool) or not isinstance(payload.timestamp, int):
        raise ValueError("proof payload has invalid timestamp")
    return payload
