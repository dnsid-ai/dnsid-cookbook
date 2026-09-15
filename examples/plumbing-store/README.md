# Plumbing Store Chatbot — DNSid Provenance Demo

**What you'll build:** A conversational quote tool for a fictional plumbing company where every quote is accompanied by a JWT signed with an Ed25519 key anchored to the business's domain via a `_dnsid` TXT record. Anyone can verify the quote's authenticity and integrity without an account or access to the issuer's systems.

## Why this matters

A customer receives a plumbing quote. How do they know it hasn't been altered — by a middleman, a phishing page, or a corrupted email attachment? With DNSid:

- The quote carries a **JWT signed by a key that is cryptographically anchored to the business's domain** (`ace-plumbing.example`).
- The verification path is public DNS + HTTPS — no proprietary API, no login, no trust-me-bro.
- The signed claims (quote ID, customer name, amount) are tamper-evident: any change breaks the signature.

This is the same trust model as DKIM for email, applied to arbitrary documents.

## Prerequisites

- Go 1.22 or later

No other dependencies. The example uses only the Go standard library.

## Run it

```bash
cd examples/plumbing-store
go run .
# or: make run
```

Open **http://localhost:8080** in your browser.

## Try it

1. **Chat** — enter your name and describe a plumbing problem (e.g. "burst pipe in the basement", "dripping kitchen faucet").
2. The chatbot replies with a price estimate and a link to the **signed quote**.
3. On the quote page, copy the **JWT** from the DNSid Provenance Token section.
4. Navigate to **http://localhost:8080/verify** and paste the JWT.
5. Watch the verifier walk through each step: DNS lookup → JWKS fetch → signature check.

## Verify

A valid JWT produces:

```
✓ Parsed JWT (3 parts)
✓ Decoded header — alg=EdDSA kid=<thumbprint>
✓ Extracted issuer: ace-plumbing.example
✓ DNS: _dnsid.ace-plumbing.example → ku=http://localhost:8080/.well-known/jwks.json
✓ Fetched JWKS (1 key(s))
✓ Found key kid=<thumbprint>
✓ EdDSA (Ed25519) signature verified
✓ Not expired (exp: ...)
```

Tamper with any character in the JWT and the result flips to ❌.

## What to try next

- **Real DNS anchor** — Replace `mockDNS` with a live `net.LookupTXT("_dnsid.ace-plumbing.example")` call and publish a real `_dnsid` record for your domain.
- **Persistent keys** — Save the generated key to disk so quotes survive server restarts.
- **Use the dnsid-go SDK** — Replace the manual Ed25519 signing with `dnsid.GenerateKeyProvider()` + `agent.CreateJWT()` from `github.com/dnsid-ai/dnsid-go`.
- **PDF export** — Add a `/quote/{id}/pdf` route using a headless browser or a Go PDF library.

## Directory layout

```
examples/plumbing-store/
├── main.go      # HTTP server, handlers, JWT signing/verification, HTML templates
├── go.mod       # Standalone module, stdlib only
├── Makefile     # make run / make build
└── README.md
```

## DNSid concepts used

| Concept | Where |
|---------|-------|
| `_dnsid` TXT record | `mockDNS` map — simulates `_dnsid.ace-plumbing.example` TXT lookup |
| JWKS endpoint (`ku=`) | `GET /.well-known/jwks.json` — serves the Ed25519 public key |
| EdDSA JWT signing | `signQuoteJWT()` — signs over `base64url(header).base64url(payload)` |
| JWK thumbprint (`kid`) | `jwkThumbprint()` — RFC 7638 SHA-256 of canonical OKP JSON |
| Verification flow | `verifyToken()` — DNS → JWKS → key match → Ed25519 verify → expiry |

Spec version: `v=dnsid-draft01`
