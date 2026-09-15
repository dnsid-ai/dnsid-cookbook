# What DNSid is

A concise description of the current DNSid protocol and implementation.

## Definition

DNSid is a durable identity protocol for agents and services. It assigns an agent a fully qualified domain name (FQDN), binds that name to an accountable entity, and publishes the information needed to verify the binding, current status, operational key, and lifecycle history.

The **accountable entity** is the organization or person responsible for the agent and authorized to revoke it. DNSid identifies that entity through a domain it controls; DNSid does not decide whether the entity is trustworthy.

An agent does not need to be publicly discoverable or host a public application endpoint. Its identity endpoints need only be reachable by the verifiers expected to use them.

## What gets published

For an agent such as `alice.dev.dnsid.test`, the accountable entity publishes exactly one TXT record at `_dnsid.alice.dev.dnsid.test`. The current DNSid testnet emits this shape:

```txt
v=dnsid-draft-01;ek=https://dnsid.dnsid.test/.well-known/dnsid-ek.json;gi=dnsid.test;ku=https://alice.dev.dnsid.test/.well-known/jwks.json;lr=c2sp-tlog:testnet:https://registry.dev.dnsid.test#<stream-id>;sg=<base64url-signature>;su=https://registry.dev.dnsid.test/v1/status/alice.dev.dnsid.test
```

The exact URLs, stream identifier, and signature vary by identity. The protocol does not require the example `.well-known` paths; the complete endpoint URLs are carried in the record.

The record uses one semicolon-separated value. `v` is first on the wire, and the remaining tags are sorted by name. Its required tags are:

- `v` — the wire-profile selector. Current implementations publish `dnsid-draft-01`.
- `gi` — the governance identifier: the accountable entity's lowercase domain.
- `ek` — an HTTPS JWKS endpoint for the accountable entity's record-signing key.
- `ku` — an HTTPS JWKS endpoint for the agent's operational key.
- `lr` — a reference to the agent's stream in a lifecycle log.
- `su` — an HTTPS endpoint for the agent's current lifecycle status.
- `sg` — the accountable entity's signature over the record content.

Optional tags include `fl` for policy flags, `ka` for maximum operational-key age, and `cu` for a capabilities document.

The submitted Internet-Draft uses the literal `v=DNSid1`. Before version 1 becomes an RFC, the current CLI and SDKs deliberately publish `v=dnsid-draft-01` so a signed record names its exact draft contract. They accept exact `v=DNSid1` only as a verification-side alias and do not publish it.

## Two separate keys

DNSid separates accountability from runtime operation:

- The **accountable-entity key**, discovered through `ek`, signs the TXT record and accountable-entity-authorized lifecycle events.
- The **operational key**, discovered through `ku`, signs agent messages, challenges, and profile-defined work products. It also consents to issuance and authorizes operational-key rotation.

Each endpoint exposes exactly one current signing key in the base profile. Each JWK includes a `kid` and `alg`. The two keys must be different key material, determined by comparing their RFC 7638 JWK Thumbprints.

The `sg` value is an unpadded base64url signature made by the `ek` key. Its signing input contains every TXT tag except `sg`, sorted alphabetically by tag name, joined with semicolons without whitespace, and encoded as US-ASCII. Unknown extension tags remain part of that signed input.

Compromise of the operational key permits runtime impersonation but does not permit an attacker to forge a new owner-signed record. Compromise of the accountable-entity key permits forged accountability assertions but does not by itself provide the operational private key.

## Lifecycle and status

The **lifecycle log** is an append-only verifiable history of the identity. It preserves evidence that mutable DNS, JWKS, and status endpoints cannot preserve by themselves.

Core events are:

- `ISSUANCE` — binds the FQDN, `gi`, accountable-entity key, and initial operational key. It is signed by the accountable entity and countersigned by the initial operational key, so neither side can create the binding unilaterally.
- `KEY_ROTATION` — links the previous operational key to a new operational key. The previous key authorizes the change; the current C2SP method also requires proof of possession by the new key.
- `REVOCATION` — forcibly and permanently ends the identity, with a reason.
- `RETIREMENT` — gracefully and permanently ends the identity.
- `MIGRATION` — moves lifecycle history to another log method while preserving a verifiable reference to the previous history.

The `su` endpoint is the primary real-time status source. A verifier handling a new interactive operation obtains a sufficiently fresh response and requires protocol state `ACTIVE`. Unavailable status produces an indeterminate DNSid result; stale or non-`ACTIVE` status fails verification. A relying application may apply its own risk policy, but it must not describe unavailable status as verified `ACTIVE`.

The status endpoint and lifecycle log serve different purposes: status is the current accountable-entity declaration, while the log provides durable history and key continuity. A fresh log view does not replace the required live status check unless a separate profile explicitly says it does.

## The C2SP transparency-log method

The current implementation uses the `c2sp-tlog` log method. Its `lr` value identifies:

1. the verification scope, such as `public`, `testnet`, or `private-*`;
2. the C2SP tiled-log URL prefix; and
3. one identity-instance stream.

A C2SP verifier checks the canonical lifecycle-event bytes, event signatures, Merkle inclusion proof, signed checkpoint, accepted witness cosignatures, signed stream context, event ordering, key continuity, and—when current logged state matters—a complete stream view. One valid inclusion proof proves only that one event is present; it does not prove that a later revocation or rotation was not omitted.

The C2SP policy names the accepted log key, witness keys, and witness quorum. That policy is a trust anchor, not data to discover from the log being verified.

In the cookbook testnet, its trusted location comes only from `DNSID_LOG_POLICY_URL`. A verifier must never derive the policy URL from `DNSID_LOG_REF`, the log prefix, `/dnsid-policy` conventions, or any record-, log-, mirror-, or bundle-provided value. Fetching a policy from the same log endpoint is advisory unless its bytes or key are independently trusted.

## How verification works

For a current interactive operation, a complete DNSid verifier:

1. Resolves `_dnsid.<agent-fqdn>`, requires one unambiguous TXT record, concatenates that RR's DNS character-strings, and validates its syntax and required tags.
2. Applies DNSSEC policy. A failed DNSSEC validation makes the record unusable; an unsigned zone provides reduced, WebPKI-assisted assurance rather than DNS-rooted assurance.
3. Fetches `ek` over authenticated HTTPS, validates that its host is `gi` or below it, and verifies `sg` with its single current key.
4. Fetches `ku` over authenticated HTTPS at the agent FQDN, validates its single current key, and confirms that the `ek` and `ku` keys are distinct.
5. Uses the independently trusted log-method policy to verify the bilateral `ISSUANCE` event and the continuity chain from its initial operational key to the current `ku` key.
6. Fetches fresh status from `su` and requires `ACTIVE`.
7. Verifies the application message, token, or challenge with the operational key according to the application profile in use.

Record-signature verification alone proves only that the `ek` key signed the record. It does not prove DNS-origin authenticity, operational-key consent, current status, lifecycle continuity, or that the accountable entity is reputable.

Historical verification uses retained lifecycle events, historical key material, checkpoints, witness signatures, and inclusion proofs. It can evaluate which key and accountable entity applied at a past time even after live endpoints change, but historical evidence alone cannot establish current `ACTIVE` status.

## What DNSid does not do

DNSid does not:

- authenticate human users;
- replace TLS, the Web PKI, or DNSSEC;
- define application authorization policy;
- provide agent discovery or an agent-to-agent transport;
- attest the runtime workload that happens to hold a key;
- determine whether an accountable entity is reputable or legally qualified; or
- make an LLM part of identity verification or trust enforcement.

Protocols such as OIDC, OAuth, RFC 9421 HTTP Message Signatures, MCP, A2A, SPIFFE, and Verifiable Credentials can carry or use a DNSid identity. They remain separate layers.

## Where to learn more

- [DNSid Internet-Draft 01](https://github.com/dnsid-ai/dnsid-ietf-spec/blob/main/current-draft/draft-ihsanullah-dnsid-01.md)
- [DNSid C2SP transparency-log method](https://github.com/dnsid-ai/dnsid-ietf-spec/blob/main/log-method-extensions/c2sp-tlog-log-method.md)
- [DNSid CLI and local testnet](https://github.com/dnsid-ai/dnsid#local-testnet)
- [C2SP implementation and testnet notes](https://github.com/dnsid-ai/dnsid/blob/main/docs/c2sp-tlog.md)
- [Go SDK](https://github.com/dnsid-ai/dnsid-go)
- [Python SDK](https://github.com/dnsid-ai/dnsid-py)
- [TypeScript SDK](https://github.com/dnsid-ai/dnsid-ts)
- [Cookbook recipes](INDEX.md)
