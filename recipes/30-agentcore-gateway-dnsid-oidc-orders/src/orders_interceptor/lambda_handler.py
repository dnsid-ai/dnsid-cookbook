from __future__ import annotations

import json
import os
import time
from functools import cache
from typing import Any

from orders_common.jwt import decode_claims
from orders_common.proof import arguments_hash, sha256
from orders_interceptor.proof import ProofError, ProofVerifier, build_profile
from orders_interceptor.replay import DynamoReplayStore


PROTECTED_HEADERS = {"authorization", "x-action-proof", "x-dnsid-status", "x-dnsid-sub", "x-gateway-sentinel"}


class RequestError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def verify_request(request: dict[str, Any], verifier: ProofVerifier, expected_subject: str) -> dict[str, str]:
    headers = normalize_headers(request.get("headers"))
    body = request.get("body") if isinstance(request.get("body"), dict) else {}
    if body.get("method") != "tools/call":
        return {}
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    tool_name = str(params.get("name", "")).rsplit("___", 1)[-1]
    token = headers.get("authorization", "")
    if not token.startswith("Bearer "):
        raise RequestError("missing_token", "missing bearer token")
    try:
        claims = decode_claims(token.removeprefix("Bearer "))
        subject = required_string(claims, "sub")
        audience = single_audience(claims.get("aud"))
        jti = required_string(claims, "jti")
    except (TypeError, ValueError) as exc:
        raise RequestError("malformed_token", str(exc)) from exc
    if subject != expected_subject:
        raise RequestError("unexpected_subject", "unexpected DNSid subject")
    jws = headers.get("x-action-proof")
    if not jws:
        raise RequestError("missing_action_proof", "missing action proof")
    expected = {
        "subject": subject,
        "audience": audience,
        "token_jti_hash": sha256(jti),
        "tool_name": tool_name,
        "arguments_hash": arguments_hash(arguments),
        "session_hash": sha256(headers.get("mcp-session-id", "")),
    }
    try:
        action = verifier.verify(jws, expected, int(time.time()))
    except ProofError as exc:
        code = "dnsid_revoked" if exc.state.upper() == "REVOKED" else "action_proof_denied"
        raise RequestError(code, str(exc)) from exc
    return {"subject": subject, "status": action.identity.cached_state().lower()}


def transform_request(
    event: dict[str, Any],
    verifier: ProofVerifier,
    expected_subject: str,
    sentinel: str,
) -> dict[str, Any]:
    request = (event.get("mcp") or {}).get("gatewayRequest") or {}
    try:
        verified = verify_request(request, verifier, expected_subject)
    except RequestError as exc:
        return denied(request, exc.code, str(exc))
    headers = {
        key: value
        for key, value in normalize_headers(request.get("headers")).items()
        if key not in PROTECTED_HEADERS
    }
    if verified:
        headers.update(
            {
                "x-dnsid-sub": verified["subject"],
                "x-dnsid-status": verified["status"],
                "x-gateway-sentinel": sentinel,
            }
        )
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": {
                "body": request.get("body"),
                "headers": headers,
            }
        },
    }


@cache
def configured_verifier() -> tuple[ProofVerifier, str, str]:
    required = ["EXPECTED_DNSID_SUB", "DNSID_LOG_POLICY_URL", "GATEWAY_SENTINEL", "REPLAY_TABLE"]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError(f"missing interceptor configuration: {','.join(missing)}")
    subject = os.environ["EXPECTED_DNSID_SUB"]
    verifier = ProofVerifier(
        build_profile(subject, os.environ["DNSID_LOG_POLICY_URL"]),
        DynamoReplayStore(os.environ["REPLAY_TABLE"]),
    )
    return verifier, subject, os.environ["GATEWAY_SENTINEL"]


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        verifier, subject, sentinel = configured_verifier()
    except Exception:  # Fail closed if trusted verifier configuration cannot initialize.
        request = (event.get("mcp") or {}).get("gatewayRequest") or {}
        return denied(request, "interceptor_unavailable", "DNSid verifier initialization failed")
    return transform_request(event, verifier, subject, sentinel)


def denied(request: dict[str, Any], code: str, message: str) -> dict[str, Any]:
    body = request.get("body") if isinstance(request.get("body"), dict) else {}
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 403,
                "body": {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {"code": code, "message": message},
                },
            }
        },
    }


def normalize_headers(headers: Any) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (headers or {}).items() if value is not None}


def required_string(values: dict[str, Any], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"token missing {name}")
    return value


def single_audience(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], str) and value[0]:
        return value[0]
    raise ValueError("token must have one audience")
