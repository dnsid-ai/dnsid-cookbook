"""Egress signing: an A2A client whose every request carries an RFC 9421 signature.

The signing lives at the transport layer, not in per-call code:
`create_signed_async_http_client` returns an httpx client that signs every
request it sends — method, target URI, content type, the SHA-256 digest of
the exact body bytes, and the A2A negotiation headers. The a2a-sdk
ClientFactory is simply handed that client, so the A2A protocol code never
thinks about signatures at all.
"""

from __future__ import annotations

import uuid

from dnsid.http_signatures import HttpSignatureProfile
from dnsid.models import HttpSigningOptions

from agent_card import A2A_VERSION, DNSID_A2A_EXTENSION_URI, DNSID_A2A_SIGNATURE_TAG


class A2AClient:
    """Sends signed A2A messages to a peer agent via the a2a-sdk ClientFactory."""

    def __init__(
        self,
        http_sig: HttpSignatureProfile,
        target_url: str,
    ) -> None:
        from a2a.client.client import ClientConfig
        from a2a.client.client_factory import ClientFactory

        signing_opts = HttpSigningOptions(
            additional_components=["content-type", "a2a-version", "a2a-extensions"],
            tag=DNSID_A2A_SIGNATURE_TAG,
        )
        self._http_client = http_sig.create_signed_async_http_client(
            base_headers={
                "content-type": "application/json",
                "a2a-version": A2A_VERSION,
                "a2a-extensions": DNSID_A2A_EXTENSION_URI,
            },
            opts=signing_opts,
        )
        self._factory = ClientFactory(ClientConfig(httpx_client=self._http_client, streaming=False))
        self._target_url = target_url.rstrip("/")
        self._client = None

    async def _get_client(self):
        if self._client is None:
            self._client = await self._factory.create_from_url(self._target_url)
        return self._client

    async def aclose(self) -> None:
        await self._http_client.aclose()

    async def send_message(self, message_dict: dict) -> dict:
        """Send a message and return the reply as a dict with a 'parts' list."""
        from a2a.types.a2a_pb2 import Message, Role, SendMessageRequest

        client = await self._get_client()
        msg = Message(message_id=str(uuid.uuid4()), role=Role.ROLE_USER)
        for p in message_dict.get("parts", []):
            part = msg.parts.add()
            if "text" in p:
                part.text = p["text"]
                part.media_type = "text/plain"
        async for event in client.send_message(SendMessageRequest(message=msg)):
            if event.HasField("message"):
                return {
                    "parts": [{"text": p.text} for p in event.message.parts if p.HasField("text")]
                }
        return {}
