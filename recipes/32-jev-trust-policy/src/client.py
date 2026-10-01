"""Act as a provisioned DNSid identity, in both directions.

  client.py call METHOD PATH EXPECTED_STATUS     sign a request to the API (inbound gate)
  client.py guard DOMAIN OPERATION allow|refuse  decide whether to call a service at all (outbound)

The outbound guard is the same evaluator as the API's inbound gate, pointed
the other way: before this agent sends anything to a service it found, it
verifies the service's DNSid and asks the same policy whether to trust it.
"""

import asyncio
import os
import sys

import httpx

from dnsid import HttpSignatureProfile, identity_manager_from_environment
from facts import Interaction
from trust import Operation, Tier, evaluator_from_environment

API = "https://api.test"
STRICT = os.getenv("DNSID_RECIPE_ASSERT", "1") != "0"
BODIES = {"/v1/quotes": {"sku": "WIDGET-1", "quantity": 10}, "/v1/refunds": {"order": "A-1001", "amount": 25.0}}

# What this agent might send to a service, and the trust each needs.
OUTBOUND = {
    "order-lookup": Operation(
        Interaction("outbound", "send an order number to look up its shipping status", "low"), Tier.LIMITED),
    "customer-pii": Operation(
        Interaction("outbound", "send a customer's name, home address and phone number", "shares personal data"),
        Tier.TRUSTED),
}


def check(label: str, ok: bool) -> None:
    print(("ok    " if ok else "FAIL  ") + label, flush=True)
    if not ok and STRICT:
        raise SystemExit(1)


async def call(method: str, path: str, expected: int) -> None:
    profile = HttpSignatureProfile.from_identity_manager(identity_manager_from_environment())
    async with profile.create_signed_async_http_client() as client:
        if method == "GET":
            response = await client.get(API + path)
        else:
            response = await client.post(API + path, json=BODIES.get(path, {}))
    check(f"{method} {path} -> {response.status_code} {response.text}", response.status_code == expected)


async def guard(domain: str, operation: str, expected: str) -> None:
    op = OUTBOUND[operation]
    manager = identity_manager_from_environment()
    # An unverifiable service raises here and is refused before any policy runs.
    verified = await asyncio.to_thread(manager.verify_domain, domain)
    await asyncio.to_thread(manager.verify_log_evidence, verified)
    async with httpx.AsyncClient(timeout=10) as http:
        decision = await evaluator_from_environment(http).evaluate(verified, op.interaction)
    verdict = "allow" if op.permits(decision) else "refuse"
    check(f"guard {domain} {operation} -> {verdict} "
          f"(tier={decision.tier.name.lower()}, reasons={','.join(decision.reasons) or '-'})",
          verdict == expected)
    # An agent would now make the call, or skip it and tell its user why.


def main() -> None:
    match sys.argv[1:]:
        case ["call", method, path, expected]:
            asyncio.run(call(method.upper(), path, int(expected)))
        case ["guard", domain, operation, ("allow" | "refuse") as expected] if operation in OUTBOUND:
            asyncio.run(guard(domain, operation, expected))
        case _:
            raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
