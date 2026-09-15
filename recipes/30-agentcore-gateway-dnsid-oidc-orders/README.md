# Recipe 30 — Verify a DNSid-signed order in AgentCore Gateway

> Accept one AgentCore Gateway order from a DNS identity without exchanging a signing key or shared secret.

**Spec version:** `dnsid-draft-01`
**Status:** deploy-only
**Standards used:** OpenID Connect, RFC 7515 (JWS), RFC 7517 (JWKS), RFC 7519 (JWT), MCP, Amazon Bedrock AgentCore Gateway
**Estimated time:** ~20 minutes with AWS and DNSid credentials

---

## What you'll build

You will deploy one Model Context Protocol (MCP) `place_order` tool behind Amazon Bedrock AgentCore Gateway. A caller gets a DNSid-issued OpenID Connect (OIDC) token and signs the exact order with its DNSid operational key. A request interceptor discovers that key from the caller's domain, verifies the complete DNSid identity and live status, and accepts the order only when the token, tool arguments, session, timestamp, and one-use nonce all match.

## Why this matters

AgentCore can validate an OIDC access token, but a sensitive tool may also need proof that the current caller controls the DNS-published agent key. DNSid supplies that key and its lifecycle state from the caller's domain, so partners do not exchange shared secrets or copy public keys into configuration. This recipe accepts a valid first-contact action, then denies modified arguments and replay of the same signed action.

## Prerequisites

- An AWS account with Bedrock AgentCore Gateway, API Gateway, Lambda, DynamoDB, IAM, and CloudWatch access in `us-east-1`
- AWS credentials available to the SDK; AWS CLI v2 is useful for inspection
- [`uv`](https://docs.astral.sh/uv/) 0.12.6 with Python 3.11+
- The [`dnsid` CLI](https://github.com/dnsid-ai/dnsid/releases) and a production or lab identity it has already issued
- The identity directory containing `config.json` and `private.jwk`; if it is not the CLI's current identity, set `DNSID_CONFIG_DIR`
- The registry operator's independently trusted C2SP transparency-log policy—the rules and key used to validate issuance history—at `DNSID_LOG_POLICY_URL`. Obtain this URL from trusted operator configuration; never derive it from the DNSid record or log reference.

This is deploy-only because it creates real AWS resources. It does not substitute fixtures for DNSid or AgentCore.

## Concepts

- **DNSid identity** — a domain-bound cryptographic identity. Its `_dnsid.<domain>` TXT record points verifiers to the operational public keys, accountable owner, issuance log, and live status.
- **OIDC token** — a short-lived access token that AgentCore validates for issuer and Gateway audience before invoking recipe code.
- **JWS action proof** — a compact JSON Web Signature containing the order details. It proves control of the DNSid operational key and prevents the order from being changed in transit.
- **C2SP transparency log** — the append-only issuance history that connects the accountable owner to the operational key. Its policy URL is independent trusted verifier configuration.
- **Replay nonce** — a random one-use value in each signed action. DynamoDB reserves it so the same valid action cannot run twice.

## Running system

| Process | Where | Role |
|---|---|---|
| Caller | Your machine | Mints the OIDC token and signs one order with `dnsid-py` |
| AgentCore Gateway | AWS | Validates the token and exposes one MCP tool |
| Request interceptor | AWS Lambda | Verifies the DNSid JWS, identity lifecycle, call binding, freshness, and nonce |
| Replay table | AWS DynamoDB | Rejects reuse of a valid nonce |
| Order target | API Gateway + AWS Lambda | Accepts only context injected by the verified Gateway path |

## Step 1 — Configure and check credentials

```bash
cd recipes/30-agentcore-gateway-dnsid-oidc-orders
export DNSID_CONFIG_DIR=/path/to/your/dnsid/identity # omit for the current CLI identity
export DNSID_LOG_POLICY_URL=https://operator.example/path/to/trusted-policy
make bootstrap
```

The identity domain comes from its signed CLI configuration; there is no second domain setting to mistype. Bootstrap prints the selected domain, trusted policy URL, and AWS account without exposing tokens or private keys.

## Step 2 — Sign exactly one action

The caller creates one compact JWS in `src/orders_client/action.py`:

```python
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
```

The token ID binds the proof to one OIDC token; the argument and session hashes bind it to one MCP call; the timestamp and nonce limit when and how often it can run.

## Step 3 — Verify through DNSid

The interceptor's core verification is in `src/orders_interceptor/proof.py`:

```python
def verify(self, jws: str, expected: dict[str, str], now: int) -> VerifiedAction:
    try:
        signed, identity = self.profile.verify_jws(jws)
        payload = decode_payload(signed)
    except (DNSidError, TypeError, ValueError) as exc:
        raise ProofError(
            "DNSid action proof verification failed",
            state=str(getattr(exc, "agent_state", "") or ""),
        ) from exc
    if identity.domain != payload.subject:
        raise ProofError("action proof subject does not match signer identity")
    for field, value in expected.items():
        if getattr(payload, field) != value:
            raise ProofError(f"action proof does not match {field}")
    if abs(now - payload.timestamp) > self.max_age:
        raise ProofError("action proof is stale")
    if identity.cached_state().upper() != "ACTIVE":
        raise ProofError(f"DNSid identity is {identity.cached_state().lower()}", state=identity.cached_state())
    try:
        self.replay_store.reserve(
            payload.nonce,
            max(1, payload.timestamp + self.max_age - now + 1),
            now,
        )
    except ReplayError as exc:
        raise ProofError(str(exc)) from exc
    return VerifiedAction(payload, identity)
```

`verify_jws` does the DNSid work: resolve the record, verify owner and operational signatures plus the independently trusted log history, fetch the DNS-published JWKS, verify the JWS, and check live lifecycle status. The remaining checks bind that verified identity to this exact call.

## Step 4 — Deploy the Gateway path

```bash
make deploy
```

This idempotently creates one Gateway, one API Gateway route, two Lambdas, one replay table, and their least-privilege roles. Deployment state stays under `.artifacts/`.

## Run it

```bash
make run
```

Expected output:

```text
✓ AgentCore accepted the DNSid OIDC token for <your-agent-domain>
✓ interceptor resolved the DNSid key and verified the signed action
✓ order accepted: 2 × LABEL-CASE
```

## Verify

```bash
make verify
```

Expected output:

```text
✓ valid DNSid action accepted for <your-agent-domain>
✓ modified order denied: action proof does not match arguments_hash
✓ repeated action denied: nonce already used
```

The verification is one-shot and exits nonzero if any assertion fails. Remove all recipe-owned AWS resources when finished:

```bash
make clean
```

## What to try next

- Change `quantity` after signing and observe the interceptor reject the argument hash.
- Set the proof timestamp more than five minutes in the past and observe freshness rejection.
- With a disposable identity, revoke it and observe a still-unexpired token fail DNSid verification.

## Glossary

- **C2SP** — a compact transparency-log protocol used to prove that identity issuance appears in an independently verifiable append-only history.
- **JWKS** — JSON Web Key Set, the standard document containing the DNS-published operational public key.
- **MCP** — Model Context Protocol, the tool-call protocol exposed by AgentCore Gateway.
- **Operational key** — the agent-held private key used to sign actions; it is distinct from the accountable owner's key.
- **Verifier** — the interceptor code that decides whether the signed action belongs to an active DNSid identity and matches the current request.
