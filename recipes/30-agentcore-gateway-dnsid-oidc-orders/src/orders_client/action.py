from __future__ import annotations

import secrets
import time
from typing import Any

from dnsid import JoseProfile

from orders_common.proof import ActionPayload, arguments_hash, encode_payload, sha256


def sign_action(
    profile: JoseProfile,
    *,
    subject: str,
    audience: str,
    token_jti: str,
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    payload = ActionPayload(
        subject=subject,
        audience=audience,
        token_jti_hash=sha256(token_jti),
        tool_name=tool_name,
        arguments_hash=arguments_hash(arguments),
        session_hash=sha256(session_id),
        timestamp=int(time.time()),
        nonce=secrets.token_urlsafe(18),
    )
    return profile.create_jws(encode_payload(payload))
