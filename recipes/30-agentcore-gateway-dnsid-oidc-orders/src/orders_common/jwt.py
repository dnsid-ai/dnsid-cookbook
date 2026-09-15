from __future__ import annotations

import base64
import json
from typing import Any


def decode_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(payload))
    if not isinstance(decoded, dict):
        raise ValueError("JWT payload must be an object")
    return decoded
