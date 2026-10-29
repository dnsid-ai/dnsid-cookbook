"""Send one signed request twice, byte for byte. The second must be rejected.

Run under `dnsid local run peer -- uv run python -u verify/replay.py <url>`.
"""

import asyncio
import json
import sys

from dnsid import HttpSignatureProfile, identity_manager_from_environment
from dnsid.models import HttpRequest, HttpSigningOptions
from langchain_dnsid import TAG


async def main(url: str) -> None:
    idm = identity_manager_from_environment()
    body = json.dumps({"text": "hello"}).encode()
    signed = HttpSignatureProfile.from_identity_manager(idm).create_signed_http_request(
        HttpRequest(method="POST", url=url, headers={"content-type": "application/json"}, body=body),
        HttpSigningOptions(additional_components=["content-type"], tag=TAG),
    )
    # The SDK's plain (unsigning) client: local registry DNS and CA, nothing else.
    async with idm.create_dnsid_async_http_client() as client:
        for attempt in ("first", "replay"):
            resp = await client.post(url, headers=signed.headers, content=body, timeout=120)
            print(f"{attempt}: {resp.status_code} {resp.text}")


asyncio.run(main(sys.argv[1]))
