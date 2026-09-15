"""A2A agent card with the DNSid HTTP Message Signature extension.

An A2A agent card is the machine-readable capability document an agent serves
at /.well-known/agent-card.json. This module builds one that declares, as a
*required* extension, that every inbound request must carry a DNSid-bound
RFC 9421 HTTP Message Signature — so a compliant caller knows the contract
before sending its first message.

Mirrors the TypeScript agent card in dnsid-ts/examples/a2a.
"""

from __future__ import annotations

import asyncio
import json

from a2a.types.a2a_pb2 import AgentCard, StringList

from dnsid.jose import JoseProfile

# ---------------------------------------------------------------------------
# Shared protocol constants — referenced by middleware.py and client.py.
# ---------------------------------------------------------------------------

DNSID_A2A_EXTENSION_URI = (
    "https://example-provider.example/a2a/extensions/dnsid-http-message-signatures/v1"
)
DNSID_A2A_SIGNATURE_TAG = "a2a-dnsid-http-sig-v1"
A2A_VERSION = "1.0"

# The request parts every signature must commit to. `content-digest` binds the
# body; `a2a-version` and `a2a-extensions` bind the protocol negotiation
# headers so they cannot be stripped or altered in transit.
REQUIRED_SIG_COMPONENTS = [
    "@method",
    "@target-uri",
    "content-type",
    "content-digest",
    "a2a-version",
    "a2a-extensions",
]


def build_agent_card(domain: str, url: str, provider_url: str = "") -> AgentCard:
    """Build an A2A AgentCard for a DNSid echo agent.

    The card declares the DNSid HTTP Message Signature extension as a required
    capability, mirroring the TypeScript agent card structure.
    """
    if not provider_url:
        provider_url = f"https://{domain}"

    card = AgentCard()
    card.name = "Example DNSid Echo Agent"
    card.description = (
        "A minimal A2A agent that echoes text input and requires "
        "DNSid-bound HTTP Message Signatures."
    )
    card.version = "0.2.0"

    iface = card.supported_interfaces.add()
    iface.url = url
    iface.protocol_binding = "JSONRPC"
    iface.protocol_version = A2A_VERSION
    iface.tenant = ""

    # Provider metadata
    try:
        card.provider.organization = "Example Provider"
        card.provider.url = provider_url
        card.documentation_url = f"{provider_url.rstrip('/')}/docs/echo-agent"
    except AttributeError:
        pass  # older a2a-sdk protobuf without provider/documentation_url fields

    card.capabilities.streaming = False
    card.capabilities.push_notifications = False

    # DNSid extension capability
    try:
        ext = card.capabilities.extensions.add()
        ext.uri = DNSID_A2A_EXTENSION_URI
        ext.description = (
            "Requires DNSid validation, RFC 9421 HTTP Message Signatures, "
            "and mTLS for inbound requests."
        )
        ext.required = True
        try:
            from google.protobuf.struct_pb2 import Struct

            params = Struct()
            params.update(
                {
                    "dnsidSubject": "selected-interface-host",
                    "runtimeProof": "http-message-signature",
                    "signatureInputHeader": "Signature-Input",
                    "signatureHeader": "Signature",
                    "requiredSignatureTag": DNSID_A2A_SIGNATURE_TAG,
                    "keyidSyntax": "<caller-dnsid-subject>#<jwks-kid>",
                    "keyResolution": "dnsid-ku-jwks",
                    "requiredCoveredComponents": ",".join(REQUIRED_SIG_COMPONENTS),
                    "requiredSignatureParameters": "keyid,alg,created,expires,nonce,tag",
                    "contentDigest": "sha-256-required",
                    "statusCheck": "dnsid-su-active-required",
                    "providerPolicy": "provider-url-host-must-equal-or-be-subdomain-of-gi",
                    "mtls": "required-because-target-dnsid-fl-contains-mtls",
                }
            )
            ext.params.CopyFrom(params)
        except (AttributeError, ImportError):
            pass  # params field or Struct not available in this sdk version
    except AttributeError:
        pass  # older a2a-sdk protobuf without extensions field

    card.default_input_modes.append("text/plain")
    card.default_output_modes.append("text/plain")

    sk = card.skills.add()
    sk.id = "echo"
    sk.name = "Echo"
    sk.description = "Returns the input text unchanged."
    sk.tags.extend(["echo", "test", "diagnostic"])
    try:
        sk.examples.extend(["Echo: hello world", "Return this exact text: ping"])
        sk.input_modes.append("text/plain")
        sk.output_modes.append("text/plain")
    except AttributeError:
        pass  # older a2a-sdk

    # Security scheme: dnsidMtls (mTLS required when fl=mtls is set in DNSid record)
    try:
        sc = card.security_schemes["dnsidMtls"]
        sc.mtls_security_scheme.description = (
            "Mutual TLS is required when this agent's DNSid record contains fl=mtls."
        )
        req = card.security_requirements.add()
        req.schemes["dnsidMtls"].CopyFrom(StringList())
        try:
            sk_req = sk.security_requirements.add()
            sk_req.schemes["dnsidMtls"].CopyFrom(StringList())
        except AttributeError:
            pass
    except (AttributeError, KeyError):
        # Fall back to the httpSig scheme for older a2a-sdk versions.
        sc = card.security_schemes["httpSig"]
        sc.http_auth_security_scheme.scheme = "signature"
        sc.http_auth_security_scheme.description = (
            "RFC 9421 HTTP Message Signatures; keyid must be the sender's FQDN"
        )
        req = card.security_requirements.add()
        req.schemes["httpSig"].CopyFrom(StringList())

    return card


def _stable_json(obj: object) -> str:
    """Serialize with sorted keys and no None values, for a stable JWS payload."""
    if obj is None or not isinstance(obj, (dict, list)):
        return json.dumps(obj, separators=(",", ":"))
    if isinstance(obj, list):
        return "[" + ",".join(_stable_json(v) for v in obj) + "]"
    entries = sorted((k, v) for k, v in obj.items() if v is not None)
    return (
        "{"
        + ",".join(
            json.dumps(k, separators=(",", ":")) + ":" + _stable_json(v) for k, v in entries
        )
        + "}"
    )


async def sign_agent_card(card: AgentCard, jose: JoseProfile, domain: str) -> None:
    """Attach a detached JWS over the card so recipients can verify its authenticity.

    The signature is computed over a canonical JSON form of the card with the
    signatures field removed, then stored on the card itself.
    """
    try:
        from google.protobuf.json_format import MessageToDict

        card_dict = MessageToDict(card, preserving_proto_field_name=True)
        card_dict.pop("signatures", None)
        payload = _stable_json(card_dict).encode()
        jws = await asyncio.to_thread(jose.create_jws, payload)
        protected, _, signature = jws.split(".")
        sig = card.signatures.add()
        sig.protected = protected
        sig.signature = signature
    except Exception as exc:
        print(f"[{domain}] warning: agent card signing failed: {exc}")
