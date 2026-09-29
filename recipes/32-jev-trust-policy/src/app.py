"""Evaluate a signed request: DNSid evidence first, human trust policy second."""
import asyncio
import json
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException, Request

from dnsid import HttpRequest, HttpSignatureProfile, HttpVerificationOptions, identity_manager_from_environment
from dnsid.exceptions import VerificationError
from policy import permits

if not os.getenv("DNSID_LOG_POLICY_URL"):
    raise RuntimeError("DNSID_LOG_POLICY_URL required: launch with dnsid local run")
manager = identity_manager_from_environment()
profile = HttpSignatureProfile.from_identity_manager(manager)
model = httpx.AsyncClient(timeout=10)
app = FastAPI()
log = logging.getLogger("counterparty-trust")
PUBLIC_URL = os.environ["DNSID_PUBLIC_URL"].rstrip("/")
VERIFY = HttpVerificationOptions(required_components=["@method", "@authority", "@target-uri", "content-digest"])


@app.post("/evaluate")
async def evaluate(request: Request):
    # Bound untrusted input before DNSid verification or model evaluation.
    if request.headers.get("content-length", "").isdigit() and int(request.headers["content-length"]) > 3000:
        raise HTTPException(413)
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > 3000:
            raise HTTPException(413)

    # PUBLIC_URL is trusted deployment configuration, never a forwarded-host header.
    target = PUBLIC_URL + request.scope["raw_path"].decode("ascii")
    if request.scope["query_string"]:
        target += "?" + request.scope["query_string"].decode("ascii")
    signed = HttpRequest(method=request.method, url=target, headers=dict(request.headers), body=body)
    try:
        # Includes verify_domain: DNS, record signature, key, lifecycle binding, live status,
        # and RFC 9421 request signature/body integrity. Nothing has reached Jev yet.
        verified = await asyncio.to_thread(profile.verify_signed_http_request, signed, VERIFY)
        log_state = await asyncio.to_thread(manager.verify_log_evidence, verified)
    except VerificationError as exc:
        raise HTTPException(503 if exc.transient else 401,
                            "identity verification unavailable" if exc.transient else "invalid identity or signature") from exc

    try:
        context = json.loads(body.decode("utf-8"))
        if not isinstance(context, dict) or not context:
            raise ValueError("expected a nonempty JSON object")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "request context must be a JSON object") from exc

    # Only SDK-verified facts go into evidence. Caller-supplied claims stay in context.
    evidence = {"domain": verified.domain, "accountable_entity": verified.record.gi,
                "dnssec": verified.dnssec_state.name, "status": verified.cached_state(),
                "policy_flags": sorted(verified.record.policy_flags()),
                "log_state": log_state.logged_state,
                "log_freshness": log_state.freshness_time.isoformat(),
                "request_signature_verified": True}
    view = {"method": request.method, "path": request.url.path,
            "query": request.url.query, "body": context}
    try:
        allowed = await permits(evidence, view, model)
    except (httpx.HTTPError, ValueError, KeyError, TypeError, OverflowError) as exc:
        log.warning("decision server unavailable or malformed: %s", exc)
        raise HTTPException(503, "decision server unavailable") from exc
    log.info("counterparty=%s decision=%s", verified.domain, "proceed" if allowed else "deny")
    if not allowed:
        raise HTTPException(403, "trust policy denied or uncertain")
    # Demo gate only: an application would now dispatch this verified request.
    return {"decision": "proceed", "counterparty": verified.domain}
