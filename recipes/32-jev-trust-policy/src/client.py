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
from trust import TrustEvaluator

API = "https://api.test"
STRICT = os.getenv("DNSID_RECIPE_ASSERT", "1") != "0"
REFUND = {"order": "A-1001", "amount": 25.0}


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
            response = await client.post(API + path, json=REFUND)
    check(f"{method} {path} -> {response.status_code} {response.text}", response.status_code == expected)


async def guard(domain: str, operation: str, expected: str) -> None:
    manager = identity_manager_from_environment()
    # An unverifiable service raises here and is refused before any policy runs.
    verified = await asyncio.to_thread(manager.verify_domain, domain)
    await asyncio.to_thread(manager.verify_log_evidence, verified)
    async with httpx.AsyncClient(timeout=10) as http:
        evaluator = TrustEvaluator(http)
        decision = await evaluator.evaluate(verified, operation)
    verdict = "allow" if evaluator.permits(decision, operation) else "refuse"
    check(f"guard {domain} {operation} -> {verdict} "
          f"(tier={decision.tier.name.lower()}, reasons={','.join(decision.reasons) or '-'})",
          verdict == expected)
    # An agent would now make the call, or skip it and tell its user why.


def main() -> None:
    match sys.argv[1:]:
        case ["call", method, path, expected]:
            asyncio.run(call(method.upper(), path, int(expected)))
        case ["guard", domain, ("order-lookup" | "customer-pii") as operation, ("allow" | "refuse") as expected]:
            asyncio.run(guard(domain, operation, expected))
        case _:
            raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
