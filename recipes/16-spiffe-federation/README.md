<!-- DRAFT: technical draft pending editorial review. Wording, tagline and narrative sections are not final.
     Transcript blocks marked "to be captured" must be replaced with output from a real run before merge. -->

# Recipe 16 — DNSid-verified SPIFFE/SPIRE federation

> Gate cross-organization SPIFFE federation on a DNSid-signed federation binding: the signer's live DNSid identity under a pinned governance domain, plus fresh transparency-log evidence. Revoking the signer withdraws federation trust for new connections automatically.

**Spec version:** `dnsid-draft-01`
**Status:** runnable
**Standards used:** SPIFFE (X.509-SVID, trust bundles, federation), RFC 7515 (JWS), RFC 7638 (JWK thumbprints), C2SP tlog (transparency log, signed checkpoints, witness cosignatures)
**Estimated time:** ~30 minutes (the first `make bootstrap` builds four container images)

---

## What you'll build

Two organizations, Acme (`acme.test`) and Rackloria (`rackloria.test`), each run their own SPIFFE trust domain with SPIRE. Acme runs a **federation controller** that is the only thing allowed to install Rackloria's SPIFFE trust bundle into Acme's SPIRE server. It installs the bundle only after it has verified a federation binding that Rackloria signed with a DNSid identity. That means checking the signer's identity, Rackloria's pinned governance domain and entity key, every CA key Rackloria serves, and fresh lifecycle evidence from DNSid's transparency log. When Rackloria's federation signer identity is revoked, the controller notices on its own and removes the bundle. New cross-domain connections then fail, while Acme's internal traffic carries on.

## Why this matters

<!-- DRAFT: narrative pending editorial review -->
SPIFFE federation already standardizes *how* one trust domain accepts another's workload identities: fetch the other side's trust bundle from its bundle endpoint. What it leaves to each operator is *whether* to trust that endpoint and the organization behind it, and for how long. In practice that is a URL and a key exchanged by email and then left in place indefinitely. This recipe makes that decision explicit and continuously re-checked:

- **DNSid** provides accountable identity and lifecycle evidence: who signed the binding, which organization governs that signer, and whether the signer is still active according to an append-only, witnessed transparency log.
- **SPIFFE** keeps authenticating every workload with short-lived X.509-SVIDs, exactly as before.
- **Application policy** still decides authorization: each API admits only the SPIFFE IDs on its own allow-list.

After this recipe, revoking one DNSid identity withdraws a cross-organization trust relationship within seconds, with nobody touching Acme's systems. Withdrawal stops *new* connections. DNSid does not terminate TLS sessions that are already established; Act 3 shows this explicitly.

## Prerequisites

- Docker Engine 25+ with Docker Compose v2 (running). The images are `linux/amd64`; on Apple silicon they run under emulation, which is slower.
- `make`, `curl`, `dig`
- [`uv`](https://docs.astral.sh/uv/) (Python 3.11+)
- The `dnsid` CLI — `brew install dnsid-ai/tap/dnsid`, or download a binary per the [installation docs](https://docs.dnsid.ai/cli-installation) and put it on `PATH`
- Host port **443** free: the DNSid local registry's TLS proxy must listen on 443 (see [What goes wrong](#what-goes-wrong)). Host ports 7963, 7965 and 18080–18090, 18443 are also used (all bound to 127.0.0.1).

## Concepts

- **SPIFFE trust domain and bundle** — a trust domain (`acme.test`) is an administrative boundary for workload identities (`spiffe://acme.test/purchasing`). Its *trust bundle* is the set of CA public keys that verify those identities. Accepting another domain's bundle is what lets workloads authenticate across the boundary: that is *federation*.
- **The DNSid local registry** — a disposable, fully local DNSid deployment (DNS server, registry, transparency log, TLS proxy) that the `dnsid` CLI runs in Docker via `dnsid local`. This recipe gives it its own state directory (`.dnsid-local/`), so it never touches your default `~/.dnsid-local`.
- **Governance ID and entity key** — every DNSid identity names the organization accountable for it (its governance ID, here `rackloria.test`). That organization signs its identities' records with its *entity key*. Acme's policy pins both, so a valid identity from a different organization, or a different key claiming to be Rackloria, is rejected.
- **Federation signer** — a disposable DNSid identity *beneath* Rackloria's governance domain (`spire-fed-<time>-<hex>.rackloria.test`) that signs the federation binding. It is not Rackloria's organizational identity. Act 3 revokes the signer; Rackloria's governance ID and entity key are unchanged. A revoked signer is never reused, and it is not replaced automatically.
- **Federation binding** — a JWS (a signed JSON payload) from the signer stating which trust domain, bundle endpoint, and CA keys (by SPKI SHA-256) it vouches for, with a sequence number and a short lifetime.
- **C2SP transparency log** — an append-only log of every DNSid identity's lifecycle events (issuance, revocation, …). Independent witnesses cosign its *checkpoints*. The controller requires a fresh, witness-cosigned checkpoint showing the signer is still ACTIVE.

## Running system

| Process | Where | Role |
|---|---|---|
| DNS server | local registry container, `127.0.0.1:7963` | Serves live `_dnsid.<identity>.test` TXT records |
| Registry + transparency log | local registry container, `127.0.0.1:7965` | Registration, status, publication, C2SP log |
| TLS proxy | local registry container, `127.0.0.1:443` | Serves identity keys, status and log policy over HTTPS with a local CA |
| `acme-server`, `acme-agent` | Compose | Acme's SPIRE server and agent (trust domain `acme.test`) |
| `rackloria-server`, `rackloria-agent` | Compose; bundle endpoint `127.0.0.1:18443` | Rackloria's SPIRE server and agent (trust domain `rackloria.test`) |
| `acme-purchasing` | Compose; status `127.0.0.1:18080` | Acme client; calls inventory and the supplier API over mTLS |
| `acme-inventory` | Compose; status `127.0.0.1:18081` | Acme internal API |
| `rackloria-supplier-api` | Compose; status `127.0.0.1:18082` | Rackloria API; allow-lists `spiffe://acme.test/purchasing` |
| `acme-dnsid-controller` | Compose; status `127.0.0.1:18085` | Acme's DNSid federation controller (the only writer of Acme's `rackloria.test` bundle) |
| `rackloria-publisher` | Compose; status `127.0.0.1:18090` (Act 2 onwards) | Signs and serves Rackloria's federation binding |

The local registry containers are CLI-managed. `compose.yaml` contains only SPIRE, the workloads, the publisher and the controller; the last two join the local registry's Docker network as clients.

## Step 1 — Bring up the local registry and two SPIRE trust domains

```bash
make bootstrap
```

`scripts/bootstrap.sh` runs `dnsid local up --zone test --state .dnsid-local …`, builds the images, starts both SPIRE servers and agents, registers the workloads (selected by Unix uid), and starts them. Rackloria trusts Acme through **standard** SPIFFE federation (`federates_with` in `spire/rackloria/server.conf`). Only Acme's acceptance of Rackloria is DNSid-gated, and Acme's server config deliberately has no `federates_with` for Rackloria:

```hcl
# spire/acme/server.conf
# Acme deliberately has NO federates_with block for rackloria.test.
# SPIRE would otherwise refresh Rackloria's bundle on its own, bypassing the DNSid gate.
```

## Step 2 — Provision Rackloria's federation signer

On a first install, bootstrap issues the signer identity through the CLI harness (`scripts/identity.py`):

```bash
dnsid local agent ensure --state .dnsid-local --upstream http://127.0.0.1:18099 \
  spire-fed-<time>-<hex>.rackloria.test -- dnsid log issue --domain spire-fed-<time>-<hex>.rackloria.test
```

The signer serves nothing through the local TLS proxy, so its `--upstream` is a placeholder. The publisher runs in a container, which `dnsid local run` cannot wrap, so it receives that identity's CLI-derived environment (`dnsid local agent ensure … --format dotenv`) instead, filtered to an allowlist that never includes the registry API key. It also receives a read-only copy of only that identity's key directory.

Every later `make bootstrap` reuses that same signer, and only after the registry positively reports it ACTIVE. It never issues a second one: if the signer is revoked, retired, missing, or its status cannot be confirmed (for example, the registry times out), bootstrap stops and says why. Issuing is allowed only on a first install, with no earlier signer, pin or checkpoint store present.

<!-- Transcript to be captured from a real run: `dig @127.0.0.1 -p 7963 _dnsid.<signer> TXT +short` -->

## Step 3 — Write Acme's federation policy

Acme's decision record is `config/federation-policy.template.toml`, rendered into `.state/controller/policy.toml`:

```toml
[federation]
trust_domain = "rackloria.test"                 # the SPIFFE trust domain this policy governs
governance_id = "rackloria.test"                # the only DNSid governance ID allowed to speak for it
entity_key_thumbprints = [ ... ]                # pinned RFC 7638 thumbprint(s) of Rackloria's entity key
signer_pattern = "spire-fed-*.rackloria.test"   # DNSid identities allowed to sign the binding
federated_entries = ["spiffe://acme.test/purchasing"]

[verification]
poll_interval_s = 5
checkpoint_freshness_s = 300
unavailable_grace_s = 30
```

Two values are captured at bootstrap from the local registry: the entity-key pin and the C2SP log trust policy. The pin is the RFC 7638 thumbprint of the key served at the `ek=` URL in the signer's published `_dnsid` record, read from this recipe's own DNS resolver. `scripts/identity.py` accepts that URL only if the record's `gi=` is exactly `rackloria.test` and the URL is HTTPS on `rackloria.test` or one of its subdomains. The CLI does not export `DNSID_EK_URL`; if a future version does, it must match. The log trust policy comes from `DNSID_LOG_POLICY_URL`, never from the log or the identity record. Both are trust on first use, acceptable for a local recipe. In production, obtain both out of band.

## Step 4 — The controller's decision, every cycle

Every 5 seconds the controller (`src/dnsidfed/reconcile.py`) fetches the binding and verifies it with a **brand-new** DNSid verifier, so lifecycle status is never served from a cache:

```python
# src/dnsidfed/verifier.py
registry = create_c2sp_tlog_verification_registry(C2spTlogVerificationOptions(
    policy_document=log_policy,
    transport_config=transport,
    trusted_checkpoint_store=checkpoint_store,       # shared by every cycle; see Step 5
    checkpoint_freshness_ms=int(v.checkpoint_freshness_s * 1000),
    max_clock_skew_ms=int(v.clock_skew_s * 1000),
))
return IdentityManager.for_verification(
    IdentityManagerDependencies(log_registry=registry),
    verification=VerificationConfig(status_check_interval=timedelta(0), trusted_entities=[pin]),
    transport=transport,
)
```

Only if every check passes does it install or keep Rackloria's bundle in Acme's SPIRE server. The checks are:

1. the signer's identity, live status and the governance and entity-key pin;
2. fresh C2SP evidence that the signer is ACTIVE;
3. the policy's signer pattern, trust domain, endpoint, statement age and an anti-rollback sequence;
4. that every CA key Rackloria's bundle endpoint actually serves is in the signed set.

If they all pass, the controller runs `bundle set` and adds `federatesWith` to the approved entries. Outcomes:

- **ALLOW** — install or keep the bundle.
- **DENY** — a definitive failure (revoked signer, wrong organization or key, bad signature, log rollback, …): withdraw immediately with `bundle delete -mode dissociate`.
- **HOLD** — an indeterminate failure (evidence or binding temporarily unavailable): add nothing, and withdraw once 30 s pass without a full verification.

No failure path leads to ALLOW.

## Step 5 — Keep the log honest across cycles and restarts

Building a fresh verifier every cycle would also forget which transparency-log checkpoint was last trusted. A log that was rolled back could then hide a revocation. The controller therefore shares one durable trusted-checkpoint store (`src/dnsidfed/checkpoints.py`) across all cycles and restarts:

- `make bootstrap` initializes it once, on the first install (`dnsidfed.checkpoints ensure-initialized`, run in the controller image); later runs keep it. The controller never creates it.
- If the store disappears, is corrupted, or changes behind the controller's back, the controller fails closed: it DENYs and withdraws until an operator recovers it (see [What goes wrong](#what-goes-wrong)).
- A checkpoint that does not extend the trusted one (rollback or fork) is a definitive DENY (`LOG_INCONSISTENT`).

The store has limits. Anyone who can write the controller's state directory can delete it together with its journal, which looks like a fresh install, or swap in an older copy while the controller is stopped. The first checkpoint per log is trusted on first use. Rollback detection against **real** signed checkpoints from a live log has not yet been demonstrated: the offline tests cover the store and how its errors are handled, not the SDK's Merkle consistency check. See `architecture.md`, "Trusted checkpoint store" and "Validation status".

## Run it

```bash
make run
```

Runs the three acts with readable output. Checks are reported but do not stop the run.

### Act 1 — SPIFFE works inside Acme; Rackloria is not trusted yet

Acme purchasing calls Acme inventory over mTLS: it succeeds. Purchasing calls Rackloria's supplier API: the handshake fails at the SPIFFE layer, because Acme's SPIRE holds no `rackloria.test` bundle. The controller is running but has nothing to approve, because Rackloria has not published a binding.

### Act 2 — Rackloria publishes; Acme verifies and federates

The publisher signs a binding covering Rackloria's current CA keys. Within one or a few cycles the controller ALLOWs on its own and installs the bundle. A new cross-domain connection then succeeds, and the supplier API's **own** allow-list admits `spiffe://acme.test/purchasing`. That authorization step is separate from DNSid and SPIFFE. Purchasing also opens one long-lived TLS connection to the supplier for Act 3.

### Act 3 — The federation signer is revoked; Acme withdraws trust

The run's federation signer (not Rackloria's organization) is permanently revoked with `dnsid revoke`. The controller detects the lifecycle change on its own and withdraws the bundle (`DENY WITHDRAWN IDENTITY_NOT_ACTIVE`). New cross-domain connections fail at the SPIFFE layer, and Acme's internal traffic is unaffected.

Any one lifecycle signal is enough to DENY, while ALLOW needs all of them. In practice the first signal is the registry's live status, which the controller asks for on every cycle. The signer's JWKS then answers HTTP 410. The transparency log records the revocation later; in the local registry this took about a minute. So withdrawal does not wait for the log, and the trusted checkpoint store does not advance on a revocation: the cycle stops before the log is consulted. For the connection opened in Act 2, the recipe reports three things separately:

1. **TLS:** the established connection remains established. It was dialed once and is reused on every request.
2. **Application messages:** requests over it still receive HTTP 200.
3. **Authorization:** the supplier still evaluates its allow-list on each request, against the identity Acme's workload presented at handshake time.

Acme's trust decision about Rackloria is made **at handshake time**. Withdrawing the bundle does not re-authenticate or terminate open sessions; closing them is the application's connection policy. As a control, the recipe then closes that connection and shows that reconnecting fails at the SPIFFE layer.

## Verify

```bash
make verify
```

Runs the offline unit tests, then `make bootstrap`, then all three acts with every result asserted. It exits nonzero on any failure and dumps container state and logs.

`make verify` runs the full lifecycle **once per environment**: Act 3 revokes the signer, and a revoked signer is not replaced automatically, so a second run in the same checkout stops at bootstrap with `SIGNER UNUSABLE`. To repeat the lifecycle, use a new isolated environment (a fresh clone). There is no signer rotation command yet.

<!-- Expected output to be captured from a real run. The check lines are emitted by verify/verify.sh: -->
```
(to be captured from the first passing live run)
```

## What goes wrong

- **Port 443 is in use.** The local registry's TLS proxy must listen on 443: a non-default proxy port is written into every published URL and into the transparency log's origin, and the containers reach the proxy on 443 inside its network. Stop whatever holds 443 (often another local registry) before `make bootstrap`.
- **The controller is stopped.** An orderly stop (`make stop`, `docker stop`) withdraws only the federation trust the controller can prove it installed, and leaves everything else untouched. A crash, SIGKILL or host failure withdraws nothing: the last installed bundle stays in place until the controller runs again and re-verifies. `GET :18085/healthz` returns 503 once cycles stall. Treat the controller like any other enforcement point and alert on it. See `architecture.md`, "Operational limits".
- **Stopping vs. cleaning.** `make stop` keeps all state; `make bootstrap` resumes it with the same signer, the same entity-key pin and the same checkpoint history. Nothing is reissued or re-pinned on restart. `make clean` removes this recipe's containers, volumes, local registry and `.state/`. It refuses to delete the checkpoint history unless you pass `CONFIRM=delete-checkpoint-history`, and archives that history to `.archive/` first.
- **Bootstrap stops with a named reason.** Restart checks fail closed and say which kind of problem they hit: `RESOLVER` (this recipe's own DNS server could not be confirmed), `REGISTRY UNCERTAIN` (no definite answer from the local registry; nothing was created or replaced), `SIGNER UNUSABLE`, `MALFORMED RECORD`, `GOVERNANCE MISMATCH`, `ENTITY-KEY MISMATCH`, `CHECKPOINT STORE`, or `SPIRE REGISTRATION` (an existing registration entry differs from the expected one; it is never overwritten or deleted).
- **Known compatibility issue: the CLI reports the wrong DNS port.** After a restart, `dnsid local env` (CLI `2026.10.29-537b773`) can report `DNSID_DNS_SERVER=127.0.0.1:7753`, the CLI's default, although this recipe's local registry serves DNS on `127.0.0.1:7963`. Port 7753 may belong to a different local registry. The recipe never uses that value: it takes the port from its own `.dnsid-local/config.yml`, confirms that this instance's DNS container publishes it and answers, and prints a `NOTE` when the CLI disagrees. Use port 7963 for `dig` while following this recipe.
- **Established sessions survive revocation.** See Act 3. If your threat model requires it, add connection lifetimes or re-authentication in the application.
- **Recovering the checkpoint store.** If the controller reports `CHECKPOINT_STORE_FAILED`, it is denying on purpose. Find out why the store is missing or changed (`make checkpoints-status`), then either restore it from a known-good copy, or explicitly accept a new baseline:
  `make checkpoints-reset REASON="…"`.
  The reset stops the controller, archives the old file, and records the reason in an append-only journal. Then `make bootstrap` restarts the controller. `make clean CONFIRM=delete-checkpoint-history` starts over from nothing (keeping an archive copy).
- **Local trust assumptions.** This recipe takes shortcuts that production must not:
  - Pins and the log policy are captured from the local registry on first bootstrap (trust on first use). In production, confirm the entity-key thumbprint with the partner and obtain log trust anchors out of band.
  - The first fetch of Rackloria's bundle uses an unauthenticated channel. Its keys are accepted only if the DNSid-signed binding covers them; later fetches must be authenticated by the CA set approved before.
  - The local transparency log has a single witness, and the local DNS zone is not DNSSEC-signed (the controller records `dnssec: UNKNOWN`). The signer's status URL is served by the registry rather than by `rackloria.test` itself, which the controller notes as delegated status.
- **What this recipe does not show.** Only Acme's acceptance of Rackloria is DNSid-gated; the reverse direction is standard SPIFFE federation. The controller manages the bundle directly (`bundle set` / `bundle delete`) rather than through SPIRE's `federation` API. The local transparency log has a single witness.

## What to try next

- Rotate Rackloria's SPIRE CA (`spire-server localauthority x509 prepare|activate`). The publisher re-signs whenever the set of X.509 authorities in Rackloria's bundle changes, so the controller should update Acme's copy to match. `make verify` does not cover this; check the controller's decisions and `bundle list` yourself.
- Stop the publisher (`docker compose -p dnsid-recipe16 stop rackloria-publisher`) and watch the controller HOLD, then withdraw after the 30 s grace period.
- Change `entity_key_thumbprints` in `.state/controller/policy.toml` and restart the controller: it DENYs with `GOVERNANCE_NOT_APPROVED`.
- `make clean CONFIRM=delete-checkpoint-history && make verify` — watch the full first-install path, including checkpoint store initialization.

## Glossary

- **Bundle endpoint** — the HTTPS URL where a SPIRE server publishes its trust domain's current bundle for federated peers.
- **Checkpoint** — a signed statement of a transparency log's size and root hash at a moment in time; witnesses cosign it to confirm they saw the same log.
- **Entity key** — the organization-level DNSid key that signs the records of identities under its governance domain.
- **SPKI hash** — SHA-256 of a public key's SubjectPublicKeyInfo encoding; identifies a CA key independently of the certificate that carries it.
- **SVID** — SPIFFE Verifiable Identity Document; here an X.509 certificate naming a workload's SPIFFE ID.
