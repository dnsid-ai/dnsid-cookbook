"""An open-world API: any DNSid-verified agent may call it, and the trust
policy decides how far each one is trusted.

Order per request: bounded read -> DNSid identity + RFC 9421 signature ->
fresh non-revocation -> trust policy -> operation. Nothing reaches the
decision model until the SDK has verified who is calling.
"""

import asyncio
import json
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException, Request

from dnsid import HttpRequest, HttpSignatureProfile, HttpVerificationOptions, identity_manager_from_environment
from dnsid.exceptions import VerificationError
from trust import TrustEvaluator

if not os.getenv("DNSID_LOG_POLICY_URL"):
    raise RuntimeError("DNSID_LOG_POLICY_URL required: launch with dnsid local run")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("counterparty-trust")
manager = identity_manager_from_environment()
profile = HttpSignatureProfile.from_identity_manager(manager)
evaluator = TrustEvaluator(httpx.AsyncClient(timeout=10))
PUBLIC_URL = os.environ["DNSID_PUBLIC_URL"].rstrip("/")
MAX_BODY = 3000
app = FastAPI()

async def read_body(request: Request) -> bytes:
    if request.headers.get("content-length", "").isdigit() and int(request.headers["content-length"]) > MAX_BODY:
        raise HTTPException(413)
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            raise HTTPException(413)
    return body


async def authenticate(request: Request, body: bytes):
    # PUBLIC_URL is trusted deployment configuration, never a forwarded-host header.
    target = PUBLIC_URL + request.scope["raw_path"].decode("ascii")
    if request.scope["query_string"]:
        target += "?" + request.scope["query_string"].decode("ascii")
    components = ["@method", "@authority", "@target-uri"] + (["content-digest"] if body else [])
    signed = HttpRequest(method=request.method, url=target, headers=dict(request.headers), body=body if body else None)
    try:
        # verify_domain inside: DNS record, entity signature, keys, bilateral ISSUANCE,
        # live status, then the request signature and body digest.
        verified = await asyncio.to_thread(
            profile.verify_signed_http_request, signed, HttpVerificationOptions(required_components=components))
        await asyncio.to_thread(manager.verify_log_evidence, verified)
    except VerificationError as exc:
        log.warning("DNSid verification failed: %s", exc)
        raise HTTPException(503 if exc.transient else 401,
                            "identity verification unavailable" if exc.transient else "invalid identity or signature") from exc
    return verified


async def gate(request: Request, operation: str):
    body = await read_body(request)
    verified = await authenticate(request, body)
    try:
        decision = await evaluator.evaluate(verified, operation)
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        log.warning("decision model unavailable or malformed: %s", exc)
        raise HTTPException(503, "trust decision unavailable") from exc
    if not evaluator.permits(decision, operation):
        # Deliberately vague: naming the clause that fired helps an attacker tune its identity.
        raise HTTPException(403, "counterparty not trusted for this operation")
    try:
        payload = json.loads(body) if body else {}
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "body must be a JSON object") from exc
    return verified, payload, decision


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/v1/catalog")
async def catalog(request: Request):
    verified, _, decision = await gate(request, "catalog")
    return {"items": [{"sku": "WIDGET-1", "price": 4.5}], "counterparty": verified.domain,
            "trust": decision.tier.name.lower()}


@app.post("/v1/refunds")
async def refunds(request: Request):
    verified, payload, decision = await gate(request, "refund")
    # Demo only. A real side-effecting endpoint also needs replay and idempotency
    # enforcement: RFC 9421 freshness does not make a request one-time.
    return {"refund": "accepted", "order": payload.get("order"), "counterparty": verified.domain,
            "trust": decision.tier.name.lower()}
