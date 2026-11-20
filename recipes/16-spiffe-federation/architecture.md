<!-- DRAFT: technical draft pending editorial review. -->

# Recipe 16 — Architecture

Three layers, kept separate in the code and in every result the recipe prints:

| Layer | Question it answers | Here |
|---|---|---|
| **DNSid** | Which organization is behind this trust domain, and is its federation signer still active? | Acme's federation controller verifies Rackloria's signed binding, governance pin, and C2SP lifecycle evidence |
| **SPIFFE** | Is this workload who it claims to be? | SPIRE issues X.509-SVIDs; mTLS handshakes verify them against the trust bundles each side holds |
| **Application authorization** | May this workload call this API? | Each API's own allow-list of SPIFFE IDs (HTTP 403 otherwise) |

DNSid never sees workload traffic. It decides only whether Acme's SPIRE holds Rackloria's bundle at all.

## Components

```mermaid
flowchart LR
  subgraph cli["DNSid local registry (dnsid CLI)"]
    dns["DNS"]
    reg["Registry + status"]
    log["C2SP transparency log"]
    proxy["TLS proxy :443"]
  end

  subgraph rack["Rackloria (rackloria.test)"]
    rs["SPIRE server<br/>bundle endpoint :8443"]
    ra["SPIRE agent"]
    sup["supplier-api<br/>allow-list: acme purchasing"]
    pub["binding publisher<br/>(signer identity)"]
  end

  subgraph acme["Acme (acme.test)"]
    as["SPIRE server"]
    aa["SPIRE agent"]
    pur["purchasing"]
    inv["inventory"]
    ctl["federation controller<br/>policy + pins + checkpoint store"]
  end

  pub -- "reads own bundle (admin socket)" --> rs
  pub -- "signs binding (DNSid agent key)" --> pub
  ctl -- "GET /binding.jws" --> pub
  ctl -- "verify identity, status, log" --> cli
  ctl -- "GET bundle (bootstrap / continuity)" --> rs
  ctl -- "bundle set / delete, federatesWith (admin socket)" --> as
  as --> aa --> pur
  rs --> ra --> sup
  pur -- "mTLS" --> inv
  pur -- "mTLS (needs Rackloria bundle)" --> sup
  rs -. "standard SPIFFE federation (not DNSid-gated)" .-> as
```

## The binding

A compact JWS signed with the federation signer's DNSid operational key. Its payload:

```json
{"typ": "dnsid-spiffe-federation+v0", "iss": "<signer fqdn>", "trust_domain": "rackloria.test",
 "bundle_endpoint": {"url": "https://rackloria-server:8443", "spiffe_id": "spiffe://rackloria.test/spire/server"},
 "x509_authorities_spki_sha256": ["<b64url>", "..."], "seq": 1793000000, "iat": 1793000000, "exp": 1793000900}
```

The format is specific to this recipe: the DNSid draft defines no binding for external key material.

## One reconcile cycle

```mermaid
sequenceDiagram
  participant C as Acme controller
  participant P as Rackloria publisher
  participant D as DNSid (registry, status, C2SP log)
  participant R as Rackloria bundle endpoint
  participant S as Acme SPIRE server
  C->>P: GET /binding.jws
  C->>D: verify JWS signer: _dnsid record, entity-key pin (gi + thumbprint), live status
  C->>D: verify C2SP lifecycle: logged ACTIVE, witness-cosigned checkpoint <= 300 s,<br/>extends the trusted checkpoint (shared store)
  C->>C: policy: signer pattern, trust domain, endpoint, iat/exp, seq >= last
  C->>R: GET bundle (bootstrap: unauthenticated channel, continuity: authenticated by last approved CA set)
  C->>C: coverage: every served X.509 CA key is in the signed set
  alt all checks pass
    C->>S: bundle set + federatesWith (ALLOW)
  else definitive failure (revoked, wrong org/key, bad signature, log rollback, store failure)
    C->>S: bundle delete -mode dissociate (DENY, immediate)
  else indeterminate (binding/evidence unavailable, stale)
    C->>C: HOLD: add nothing, withdraw after 30 s without full verification
  end
```

Design rules:

- **Fresh lifecycle, persistent checkpoints.** Each cycle builds a new `IdentityManager` and log registry (`status_check_interval=0`), so status and history are never cached. One durable `CheckpointStore` is injected into every registry, so rollback and fork protection survives cycles and restarts.
- **Fail closed.** Every exception path ends in DENY or HOLD, never ALLOW. HOLD is bounded by the grace period.
- **Bootstrap vs continuity.** The first bundle fetch is over an unauthenticated channel, but the material is accepted only if every served CA key is covered by the DNSid-signed SPKI set. After the first approval, fetches must be authenticated by the previously approved CA set. Only an explicit admin re-bootstrap returns to the unauthenticated path.
- **Coverage, not equality.** Signed-but-not-yet-served keys are allowed (a CA rotation is pre-announced). Served-but-unsigned keys are never installed. JWT authorities are never installed.

## Trusted checkpoint store

`src/dnsidfed/checkpoints.py` wraps the SDK's `InMemoryCheckpointStore` with persistence:

| Situation | Behavior |
|---|---|
| First install | `make bootstrap` runs `python -m dnsidfed.checkpoints init` once; the journal records `initialized` |
| Controller restart | The same file is loaded; history is not reset |
| File missing at start, journal shows initialization | Fail closed (loss, not first start); `init` refuses |
| File missing or changed while running | Fail closed; never written back as a new baseline |
| File corrupt, second writer, write failure | Fail closed |
| Recovery | `reset --confirm-new-baseline --reason …` with the controller stopped; the old file is archived and the reset journaled |

Fail closed means the store raises `C2spCheckpointStoreError`. The SDK reports it as a non-transient `LOG_ERROR`, and the controller maps it to `DENY CHECKPOINT_STORE_FAILED` and withdraws.

**Limits.** Anyone who can write the controller's state directory can remove both the store and its journal (indistinguishable from a fresh install), or substitute an older copy while the controller is stopped. Protect that directory like the policy and pins. Keep the journal on append-only or off-host storage where that matters. After `init` or `reset`, the first checkpoint per log origin is trusted on first use.

## Revocation and established connections

Revoking the federation signer causes the next cycle to DENY. The trigger is the identity's status, its JWKS answering 410, or the log showing the revocation. Any one is enough. In the live run the live status came first, then the JWKS 410; the local log recorded the revocation about a minute later. Because the cycle stops at the first failure, the trusted checkpoint store does not advance on a revocation. The controller deletes the bundle, and the SPIRE agent removes it from Acme's workloads, so new handshakes to Rackloria fail. TLS sessions established earlier are not re-authenticated. Acme verified Rackloria's certificate once, at handshake time. Those sessions keep carrying requests, and the supplier keeps authorizing each request against the client identity presented at handshake, until the application closes them.

## Operational limits

<!-- DRAFT: pending editorial review -->

**Orderly shutdown withdraws only trust the controller can prove it installed.** On SIGTERM or SIGINT (`docker stop`, `make stop`) the controller does the following:

1. It finishes the cycle in progress.
2. Under its reconciliation lock, it refuses any further cycle.
3. It checks ownership: the controller persists the exact X.509 authority set it last installed (`managed_spki` in `state.json`), and ownership is established only if SPIRE's current `rackloria.test` bundle matches that record exactly.
4. If ownership holds:
   - The policy's own federated entries stop federating with `rackloria.test`. Any other federations on those entries are kept.
   - The bundle is deleted in SPIRE's `restrict` mode. That mode refuses while any *other* entry still federates with the trust domain, so relationships the controller does not manage are never cut. In that case the event is `DISSOCIATED` and the bundle stays.
5. If ownership cannot be established, nothing changes. Reasons include: no record, a bundle that differs from the record, or SPIRE that cannot be read. The event is `CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN` and the exit status is 3.

Every outcome writes a `CONTROLLER_SHUTDOWN` audit event. Trust anchors (for authenticated continuity), the anti-rollback sequence and the checkpoint history are kept. Compose allows 60 s for this (`stop_grace_period`).

**Abrupt failures withdraw nothing.** A crash, SIGKILL, OOM kill, Docker daemon failure or host failure runs no shutdown code: the last installed bundle stays in SPIRE. When the controller runs again, its first cycle re-verifies. A definitive failure withdraws at once. An indeterminate one withdraws once the time since the last full verification exceeds the 30 s grace, which a long outage already has. Until then, the exposure window is the downtime plus one cycle. A controller that cannot start at all, for example because its policy no longer loads, enforces nothing. Monitor `GET /healthz` (503 when cycles stall) and the container state from outside.

**Stopping and cleaning.**
- `make stop` stops the publisher first, so nothing new can be approved. It then stops the controller while SPIRE is still up, so the orderly shutdown above can run. Then it stops the rest and the recipe's local registry. Volumes, the local registry state, pins, policy, identities, the checkpoint store, its journal and the audit log are all kept. `make bootstrap` resumes from them:
  - the checkpoint store is reused, never re-initialized;
  - a pinned entity key the local registry no longer serves stops bootstrap instead of being re-pinned;
  - the federation signer is reused only after the registry positively reports it ACTIVE. A revoked, retired, missing or unverifiable signer stops bootstrap; uncertainty (a timeout, a connection error) is never treated as absence, so it can never cause a replacement. A new signer is issued only on a first install with no earlier signer, pin, checkpoint store or registry signer;
  - the published `_dnsid` record is read only from this recipe's own resolver: the port in `.dnsid-local/config.yml`, confirmed against the running DNS container of this instance and a health query. The CLI's `DNSID_DNS_SERVER` is compared and reported, never used (see README, "What goes wrong");
  - SPIRE registration entries are created only when their absence is confirmed; an existing entry is accepted only if its SPIFFE ID, parent, selectors, federation relationships and other constraints match exactly, and is never overwritten or deleted.
- `make clean` lists exactly what it removes: this recipe's Compose project, its own local registry instance, `.dnsid-local/` and `.state/`. It refuses to delete checkpoint history without `CONFIRM=delete-checkpoint-history`, and archives that history and the audit log to `.archive/checkpoints-<utc>/` (SHA-256 verified, with a manifest) before removing anything. A local registry reset starts a new transparency log, so the old history cannot be kept in place.
- Every operation is confined to the recipe:
  - The state directory must be exactly `<recipe>/.dnsid-local`, by its canonical path and not through a symlink. The Makefile refuses any `STATE` override and must be run from its own directory.
  - Compose uses this checkout's own project, `dnsid-recipe16-<hash of the canonical recipe path>` (`scripts/paths.py`), for containers, volumes, networks and image tags. An explicit, validated `RECIPE16_COMPOSE_PROJECT` selects another name: never another checkout's derived name, and a custom name only with `RECIPE16_ALLOW_CUSTOM_PROJECT=<the same name>`. Every target that touches Docker first checks ownership (`paths.py check-owner`). All containers of the project, running or stopped, must carry this checkout's working-dir label; a missing label or a failed Docker query refuses. Volumes or networks left without containers are accepted only for this checkout's own derived name. The legacy shared project `dnsid-recipe16` is used only when named explicitly: bootstrap refuses to start while it is running, and cleanup refuses it without `CONFIRM_LEGACY_PROJECT=dnsid-recipe16`.
  - `identity.py` writes only inside `.state/dnsid/`.

## Validation status

- **Offline unit tests** (`make test`, no Docker; 573 tests on Python 3.11, 3.13 and 3.14): binding validation, governance and entity-key pinning, SPKI coverage, lifecycle and evidence handling, structured SDK error mapping, fail-closed reconcile decisions, checkpoint store persistence, loss and tampering detection and audited reset, and orderly shutdown. Restart safety is covered too: resolver isolation from the CLI's `DNSID_DNS_SERVER`, signer preservation (an uncertain status never issues a replacement), named bootstrap failure categories, verified-idempotent SPIRE registrations, and recreating a stopped controller whose DNSid Local network was recreated. The shell paths run in bash 3.2 against stubbed `docker`. The SDK's own store enforces the fork rule in these tests.
- **Live run, 2026-11-19/20 (development checkout on macOS, Docker Desktop, not a clean clone).** All three acts were driven step by step, following `verify/verify.sh`. A `make stop` / `make bootstrap` resume was exercised before Act 2.
  - Act 1: Acme's internal mTLS worked. Purchasing's handshake to the supplier failed at the SPIFFE layer, with no `rackloria.test` bundle in Acme's SPIRE. The controller held (`HOLD BINDING_UNAVAILABLE`).
  - Act 2: about 3 s after the binding was signed, the controller's own cycle decided `ALLOW INSTALLED`.
    - Evidence: `dnsid_result: VERIFIED`; signer matching the policy pattern; governance `rackloria.test`; the pinned entity key; live status ACTIVE; logged state ACTIVE; a witness-cosigned checkpoint 0.2 s old.
    - The checkpoint was persisted to the durable store. The installed bundle's CA key matched Rackloria's actual CA key and the signed set.
    - Separately from the controller, the binding's Ed25519 signature was verified against the signer's published JWKS.
    - A new cross-domain handshake succeeded, and the supplier's own allow-list admitted `spiffe://acme.test/purchasing`.
  - Act 3: the signer was revoked, and the controller's own cycle decided `DENY WITHDRAWN IDENTITY_NOT_ACTIVE`.
    - Timings from the revoke call: registry REVOKED +0.19 s; DENY +3.9 s; bundle absent +4.4 s; first failing new handshake +8.3 s. The gap is the SPIRE agent delivering the change.
    - The trigger was live status (`STATUS_NOT_ACTIVE`); later cycles failed on the JWKS 410. The C2SP log recorded the revocation about 60 s later, so the withdrawal did not depend on the log.
    - The Act 2 connection stayed established, kept returning HTTP 200, and the supplier kept authorizing each request. After it was closed, reconnecting failed at the SPIFFE layer. Internal mTLS was unaffected throughout.
- **Not yet demonstrated:**
  - `make bootstrap` / `make run` / `make verify` / `make clean` end to end on a clean clone. This includes `make verify` itself; the live run above was not `make verify`.
  - Rollback or fork detection by the SDK's log reader against **real signed checkpoints** served by a live log. The offline tests show the store is shared and persisted and that the SDK's consistency errors fail closed. They do not exercise the reader's Merkle consistency check. A live integration test is planned separately. Until it passes, do not read this recipe as a demonstration of rollback protection.
