# Recipe 33 — DNSid authorization at the Google Cloud load balancer

> Verify signed agent identity at the Google Cloud load balancer, and require the verifier's attestation before the
> API serves data.

**Spec version:** `dnsid-draft-01`

**Status:** runnable locally (DNSid Local); the Google Cloud deployment needs a Google Cloud project (deploy-only)

**Standards used:** RFC 9421 (HTTP Message Signatures), RFC 7517 (JSON Web Keys), C2SP tlog (transparency log), Envoy
ext_proc (the Service Extensions callout protocol)

**Estimated time:** ~10 minutes locally; ~25 minutes for the Google Cloud deployment, most of it waiting until the
load balancer's authorization policy is in force, which varies (measured on 2026-11-16 in the latest live run: 831 s from
the up command to a working endpoint, 188 s to tear it down; earlier runs, on 2026-11-14, took 823 s and 184 s,
1,433 s and 190 s, and 835 s and 184 s; each is one observation, not a guarantee)

> **Status.** In the latest live run, on 2026-11-16, the deployment reached a working endpoint in 831 seconds and was
> removed in 188 seconds (the up command itself took 830 seconds; the script's own timer, which measures a shorter
> interval, reported 808). The run supplied the three declared inputs and a short-lived platform access token. The
> documented Application Default Credentials login was not exercised. Cold full-scan verification took 1,987 ms, within
> the 2,500 ms budget. All 30 live cases of `scripts/test-live.sh` passed, and a freshly signed request from an already
> revoked agent was refused, with its independently read status document reporting REVOKED. Each figure is one
> observation, not a guarantee. The runs of 2026-11-14 (823 and 184 seconds, a 1,657 ms cold full scan; earlier 1,433
> and 190 seconds) are historical. What the latest run did not establish is listed under
> [What is not verified yet](#what-is-not-verified-yet).

## What you'll build

A verifier that sits in front of an API on Google Cloud and lets through only requests signed by an agent with a valid
DNSid identity from an organization you trust. The authorization policy of a global external Application Load Balancer
is configured to call the verifier, on Cloud Run, through a Service Extensions authorization extension for every
request. The verifier checks the request's signature, the signer's DNSid identity, its governance (the organization
accountable for it), its lifecycle status (not revoked) and the freshness of the transparency-log evidence. A request
that passes goes on to the protected API, Demo Bank (a sample API with synthetic data), with the verified identity and
the verifier's attestation of it in headers; anything else gets the verifier's 403 with a reason code. Google applies a
new authorization policy gradually, and requests were observed reaching Demo Bank without that call while it took
effect, so Demo Bank also requires a fresh attestation from the verifier before it trusts the identity headers: a
request that bypasses the call is refused by Demo Bank itself.

```
agent ──signed HTTPS──▶ load balancer ──"may this pass?"──▶ verifier (DNSid checks)
                             │                                   │
                             │◀────── continue, or 403 ──────────┘
                             ▼ requests the policy lets through
                          Demo Bank (serves an identity only with the verifier's valid, fresh attestation)
```

You can run the same verifier on your machine first, against DNSid Local, with `make verify`; then deploy it to Google
Cloud with one command and remove it with another.

## Why this matters

RFC 9421 lets an agent sign its HTTP requests, but a signature only proves possession of a key. DNSid ties that key to
a domain, to the organization accountable for the agent, and to a public log of its issuance and revocation, all of
which a verifier can check on first contact without a shared secret. Putting that check in the load balancer means
the policy is attached to every configured route, and the API must also validate the verifier's attestation before
trusting identity headers; an agent's revocation takes effect at the edge without a redeploy or a configuration
change. DNSid answers *who is this agent, and is it still in good standing*; what
the agent may then do stays your API's decision, and the load balancer's own controls (TLS, routing, ingress) stay as
they are.

## Quick start

Deploy it to Google Cloud. You need a Google Cloud project with billing enabled, a DNSid agent registered in the
DNSid Partner Preview Console (to send the signed requests the edge allows), and the tools under
[Prerequisites](#prerequisites). To try it on your machine first, with no cloud account, see [Run it locally](#run-it).

| Input | Required | Default | What it is |
|---|---|---|---|
| `GOOGLE_CLOUD_PROJECT` | yes | none | The project to deploy into. It must already exist with billing enabled. |
| `GOOGLE_CLOUD_REGION` | no | `us-central1` | Where Cloud Run, the image repository and the image build run. |
| `DNSID_TRUSTED_GOVERNANCE` | no | `dnsid-sandbox.io` | The governance IDs the edge trusts, comma-separated. The default is the sandbox governance of Partner Preview Portal agents, used only when the variable is unset; set but empty is refused. |

Log in (Application Default Credentials):

```sh
gcloud auth application-default login
```

One command up:

```sh
GOOGLE_CLOUD_PROJECT=my-sandbox-project scripts/deploy.sh
```

It prints the endpoint (`https://<address>/accounts`) when an unsigned request there is refused by the verifier, and
writes the deployment's details to `~/.local/state/dnsid-gcp-service-extensions/<project>/deploy-out.json`.

One command down:

```sh
GOOGLE_CLOUD_PROJECT=my-sandbox-project scripts/teardown.sh
```

Nothing else is needed. The deployment enables the APIs it uses, names every resource after a unique deployment name
(`dnsid-gse-<8 hex digits>`), and keeps its Terraform state outside this directory. The endpoint uses a self-signed
certificate issued for its IP address; clients trust that certificate alone (it is in `deploy-out.json` with its
SHA-256 fingerprint) rather than skipping verification. Teardown removes everything the deployment created except the
enabled APIs.

## Prerequisites

For the local mode:

- Docker 24 or later, running.
- The `dnsid` CLI: `brew install dnsid-ai/tap/dnsid`, or a binary from the
  [installation docs](https://docs.dnsid.ai/cli-installation), on `PATH`. Written against 2026.10.29-537b773.
- Node.js 24.22.3 or later (24.x) and npm; `make`.
- A clone of this repository. Nothing else: no cloud account, no DNSid account.

For the Google Cloud deployment, also:

- **A DNSid agent registered in the DNSid Partner Preview Console**, before the first run: the deployment refuses
  every request that isn't signed by a DNSid agent, so you need one to see a request allowed.
- **gcloud** (the Google Cloud CLI), for the login, the image build and the inventory checks.
- **Terraform 1.17.2 or later** (below 2.0). The Google provider 8.11.0 and the TLS provider 4.4.2 are pinned by
  `infra/*/.terraform.lock.hcl` for Linux and macOS on amd64 and arm64, and downloaded from the public registry.
- **bash** 3.2 or later, and the usual POSIX tools (`od`, `awk`, `find`, `cp`).
- No Docker: Cloud Build builds the images.

The SDK packages (`@dnsid-ai/sdk`, `@dnsid-ai/transport`, `@dnsid-ai/log-c2sp-tlog`) are pinned to 0.37.0 in
`package-lock.json`.

### Permissions

The person deploying needs, in the project, enough to:

- enable APIs (`serviceusage.services.enable`). The deployment uses Artifact Registry, Cloud Build, Compute Engine,
  IAM, Network Security, Network Services, Cloud Run and Cloud Storage; APIs already enabled need no permission. If the
  login may not enable one, `scripts/deploy.sh` stops at the bootstrap stage and prints the `gcloud services enable`
  command for someone who may; after that, rerunning it resumes;
- create the resources below: Compute Engine load-balancing resources, Network Services and Network Security
  resources, Cloud Run services, Artifact Registry repositories, Cloud Storage buckets, service accounts;
- grant roles on the deployment's own repository and bucket, and act as the build's service account
  (`iam.serviceAccounts.actAs`);
- submit, read and cancel Cloud Build builds, and read Cloud Logging (for the live tests);
- read the project's IAM policy and those of the deployment's repository and bucket (`resourcemanager.projects.getIamPolicy`,
  `artifactregistry.repositories.getIamPolicy`, `storage.buckets.getIamPolicy`): teardown lists the grants. Without
  them teardown says so, still removes and confirms everything else, and records the policies it could not read as not
  inspected; its confirmation names only what it listed.

The project's Owner role covers all of this. With Application Default Credentials, requests are billed to the deployment
project (`user_project_override`), so no separate quota project needs setting.

## Concepts

- **DNSid identity** — a domain (here `alice.test`) with a signed `_dnsid` TXT record in DNS that names its public
  keys, its status document and its entry in a transparency log. A verifier checks all of them together.
- **RFC 9421 signature** — an HTTP request signed in two headers, `Signature-Input` (what is covered: the method, the
  target URI, the signer's identity, when it was signed) and `Signature`. Changing anything covered breaks it.
- **Governance** — the organization that issued and is accountable for an identity. The verifier trusts only the
  governance IDs it is configured with (`DNSID_TRUSTED_GOVERNANCE` in the deployment).
- **Transparency log (C2SP tlog)** — a public, append-only log where an identity's issuance and revocation are
  recorded and witnessed. The verifier requires recent (at most 300 seconds old) witnessed evidence that the identity
  was issued and has not been revoked. Which log to trust comes from configuration, never from the log itself.
- **Service Extensions authorization extension** — Google's way for an Application Load Balancer to ask a service of
  yours, over gRPC (Envoy's `ext_proc` protocol), whether each request may pass. The load balancer sends the request's
  headers; the verifier answers "continue" (with headers to set) or a 403.
- **DNSid Local** — a disposable, fully local DNSid deployment (DNS, registry, transparency log, HTTPS proxy) that the
  `dnsid` CLI runs in Docker (`dnsid local`). The local mode issues its identities there.

## Running system

Locally (`make run`):

| Process | Where | Role |
|---|---|---|
| DNS server | DNSid Local container, `127.0.0.1:7753` | Serves the `_dnsid.<agent>.test` TXT records |
| Registry and transparency log | DNSid Local container, `127.0.0.1:7755` | Issues and revokes identities; serves the C2SP log and its policy |
| HTTPS proxy | DNSid Local container, port 443 | Serves each identity's keys and status at `https://<agent>.test` with DNSid Local's CA |
| Local request path | one Node.js process on 127.0.0.1, free ports | Two local edges (HTTPS), each with its own verifier (gRPC), and Demo Bank (HTTP) |

The local edges stand where Google's load balancer stands in the deployment. They are a forwarding harness
(`local/edge.ts`), not Google's load balancer or Envoy: they pass each request's headers to the verifier the way the
authorization extension does, answer a denial with the verifier's 403, and forward a continuation to Demo Bank. One
edge's verifier trusts DNSid Local's governance; the other's trusts only a governance no identity uses, so you can see a
valid identity refused for its governance.

In Google Cloud (`scripts/deploy.sh`): the load balancer with the authorization extension, the verifier on Cloud Run
and Demo Bank on Cloud Run, in your project. See [Step 3](#step-3--deploy-it-to-google-cloud).

## Step 1 — Create local identities

```sh
make bootstrap
```

This starts DNSid Local in its own state directory, issues `alice.test`, and issues then revokes `bob.test`
(`local/recipe.ts`, `bootstrap`):

```sh
dnsid local up --zone test --state <state>/registry
dnsid local agent ensure --state <state>/registry --upstream http://127.0.0.1:9 alice.test -- dnsid log issue --domain alice.test
dnsid local agent ensure --state <state>/registry --upstream http://127.0.0.1:9 bob.test -- dnsid log issue --domain bob.test
dnsid local agent ensure --state <state>/registry --upstream http://127.0.0.1:9 bob.test -- dnsid revoke --domain bob.test --reason owner_request --yes
```

`<state>` is `${XDG_STATE_HOME:-~/.local/state}/dnsid-gcp-service-extensions/local` (set `DNSID_GCP_LOCAL_HOME` to
choose another place outside this repository). The agents only send requests, so their upstream is a placeholder;
DNSid Local serves their keys and status itself. Running `make bootstrap` again skips what is done. Your default DNSid
Local (`~/.dnsid-local`) and any other state directory are left alone.

Look at what was published:

```sh
dig @127.0.0.1 -p 7753 _dnsid.alice.test TXT +short
```

## Step 2 — Put the verifier in front of Demo Bank

The verifier is `src/`: the same code, unchanged, in both modes. For each request it decodes the `ext_proc` headers
message (`src/ext-proc.ts`), refuses anything but `GET` or `HEAD` without content (`src/preconditions.ts`), verifies
the RFC 9421 signature and resolves the signer's DNSid identity with the SDK (`src/signature.ts`, `src/identity.ts`),
checks the governance and the lifecycle with its evidence age (`src/lifecycle.ts`), and answers either a continuation
that removes every caller-supplied `x-dnsid-*` header and sets the verified ones, or a 403 whose body is the reason
code (`src/response.ts`).

Only where its trust comes from differs. In Google Cloud it trusts the DNSid-managed logs bundled with the SDK, over
the system's DNS and trust roots, with no private-address exceptions (`PRODUCTION_BACKEND`, `src/identity.ts`).
Locally, `local/backend.ts` gives it DNSid Local's log policy, DNS server, CA and `.test`-only private-address
exception, read from `dnsid local env` by `local/settings.ts`, which refuses anything else (a policy URL that isn't
HTTPS, a DNS server that isn't loopback, a private-address host outside `.test`). Nothing in `src/` reads those
settings, and the image copies only `src/` and `proto/`, so local trust can't reach the deployment.

```sh
make run
```

starts the local request path in the background (`local/stack.ts`) and prints its two edges, for example:

```
local request path: running (process 41870)
  edge (trusts <DNSid Local's governance>):   https://127.0.0.1:38211/accounts
  edge (trusts only a governance no identity uses): https://127.0.0.1:40129/accounts
  Demo Bank (behind the edges, loopback): http://127.0.0.1:35467/accounts
```

A running one is reused. Its records (the verifier's decisions, Demo Bank's requests, the edges' outcomes; never a
header value, a signature or a key) go to `<state>/run/stack.jsonl`.

## Step 3 — Deploy it to Google Cloud

```
agent ──HTTPS──▶ global external Application Load Balancer (EXTERNAL_MANAGED, port 443 only, self-signed certificate)
                   │  authorization policy (CUSTOM) on the forwarding rule
                   ▼
                 authorization extension (ext_proc over gRPC, fail_open = false, 3,000 ms timeout)
                   │                      ▲
                   ▼                      │ continue (with the verified identity headers) or 403
                 verifier on Cloud Run (h2c, ingress: internal and Cloud Load Balancing, default URL disabled)
                   ▼ requests the policy lets through
                 Demo Bank on Cloud Run (ingress: internal and Cloud Load Balancing, default URL disabled;
                                         checks the verifier's attestation before trusting identity headers)
```

The verifier lives in `src/`, Demo Bank in `origin/`, and the infrastructure in `infra/`, in two Terraform stages:

- **`infra/bootstrap`**: the APIs, the reserved global address the certificate is issued for, the Artifact Registry
  repository, and the image build's own service account, its bucket (uploaded source and build logs) and its grants,
  which cover that repository and that bucket only.
- **`infra/service`**: both Cloud Run services and their runtime service accounts (no roles), the serverless NEGs, the
  backend services (the callout's over HTTP/2; Cloud CDN off on both), the URL map (no rewrites, redirects or route
  actions), the self-signed certificate, the HTTPS proxy, the one forwarding rule (443), the authorization extension
  and the `CUSTOM` authorization policy that targets the forwarding rule. The extension forwards every request header
  to the verifier: the signature may cover any field, and every caller-supplied `x-dnsid-*` header must be seen so it
  can be removed.

`scripts/deploy.sh` runs, and records in `STATE_DIR` as it goes:

1. **bootstrap**: `terraform apply` of `infra/bootstrap`, with its state at `$STATE_DIR/bootstrap/terraform.tfstate`.
2. **images**: Cloud Build (`cloudbuild.yaml`) builds the verifier and Demo Bank for linux/amd64, runs the container
   checks of `scripts/container-smoke.sh` against them (runtime version, non-root user, image contents, startup on the
   default and a custom port, the verifier's denial of an unsigned request, Demo Bank's routes, the refusal of an empty
   governance setting, a graceful stop), and only then publishes them. The service stage gets them by digest. The
   upload is an allowlist (`scripts/lib/build-context.sh`): the two images' inputs, the build configuration, the smoke
   script and its probes, nothing else. What ends up in each image is narrower still: each Dockerfile copies only what
   its `.dockerignore` lets in.
3. **service**: `terraform apply` of `infra/service`, with its state at `$STATE_DIR/service/terraform.tfstate`.
4. **inventory**: the project's forwarding rules, proxies, URL maps, backend services and authorization policies, as
   Google's APIs list them, for the live tests' bypass checks.
5. **ready**: waits, up to 30 minutes, until unsigned `GET /accounts` requests over TLS pinned to the deployment's
   certificate, eight at a time on new connections every 5 s, get the verifier's own `403 signature_missing` on every
   probe for three minutes in a row. A new load balancer's configuration reaches its front ends gradually: for a while
   after the first denial, some requests still get its own 500 or 502, and any such answer starts the three minutes
   again. The authorization policy also takes effect gradually: for some minutes after it is created, a front end may
   forward a request to Demo Bank without asking the verifier. When Demo Bank itself answers a probe, the policy must
   then hold for ten minutes in a row. Only then does it write `DEPLOY_OUT`, atomically.

`DEPLOY_OUT` (JSON, `scripts/lib/deploy-out.ts`) holds the endpoint and protected path, the certificate and its
fingerprint, the image digests, every resource's reference, the routes the bypass tests try, the inventory and the
time each step took.

Where things go, both defaulted:

- `STATE_DIR`, default `~/.local/state/dnsid-gcp-service-extensions/<project>`: the deployment record, both stages'
  state (which holds the certificate's private key), the build records. Created private (mode 700); refused inside this
  directory.
- `DEPLOY_OUT`, default `$STATE_DIR/deploy-out.json`.

#### Login, in detail

- With **Application Default Credentials**, Terraform reads them itself. gcloud keeps its own, separate login
  (`gcloud auth login`), which you don't need: the scripts give gcloud a short-lived token minted from your Application
  Default Credentials, in a private temporary file (`CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`) removed on exit.
- **Automation** can supply a short-lived token instead: `GOOGLE_OAUTH_ACCESS_TOKEN` (Terraform) and/or
  `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE` (gcloud); either one is enough.
- Nothing uses a service account key, a `credentials` setting or a service-account login, and no token is printed or
  passed as a command argument.

### Teardown, recovery and troubleshooting (Google Cloud)

`scripts/teardown.sh` (same `GOOGLE_CLOUD_PROJECT`, and `STATE_DIR` if you set one):

1. cancels any image build of this deployment that is still queued or running (recorded ones, and any tagged with the
   deployment's name), and waits until each has stopped, so none can publish into the repository during removal;
2. lists every kind of resource the deployment creates, by its name, from Google's APIs (not from its own state), the
   grants on its repository and bucket, and any project IAM binding naming it, and prints what it found;
3. destroys the service stage, then the bootstrap stage (the repository with its images, the bucket with its sources
   and logs, the service accounts and their grants, the address);
4. lists the same again and requires that none remains;
5. only then removes the state, prints what it removed and which kinds it confirmed, and records in
   `$STATE_DIR/last-teardown.json` what it found before (`found_before`), what it could not list before
   (`not_listed_before`, with the reason), what it removed, which kinds it confirmed after (`checked_after`), which it
   could not inspect (`not_checked_after`, with the reason: only the project IAM policy, which the deployment grants
   nothing on) and what remained (`remaining_after`, nothing).

It works the same after a complete deployment, an interrupted one, or one that failed at any step: whatever either
stage created is in that stage's state. If a removal fails or the final listing finds something, it keeps the state,
says what is left, and exits 1; run it again once the cause is fixed. Running it when nothing is deployed is safe.

Kept on purpose: the **enabled APIs** (they cost nothing and other work in the project may use them). Kept by Google
Cloud as history, not as deployed resources: build records, Cloud Logging entries, and deleted service accounts'
30-day undelete window.

| Symptom | What to do |
|---|---|
| `no Google Cloud login` | Run `gcloud auth application-default login`. |
| `DEPLOY FAILED during: <step>` | Fix the cause shown above it, then run `scripts/deploy.sh` again: it resumes the same deployment (an image build already done or still running is reused, not repeated). Or remove everything with `scripts/teardown.sh`. |
| `the image build failed` | The build's log is at `gs://<deployment>-build/logs/log-<build id>.txt`; its last lines are printed. A failed container check publishes nothing. |
| Waiting for the endpoint never ends (30 minutes) | A new global load balancer can take several minutes to serve. The last answer is printed: a TLS failure means the certificate isn't served yet; a 500 means the extension can't reach the verifier; `the authorization policy is not in force yet` means a front end still forwards requests to Demo Bank without asking the verifier (Demo Bank refuses them: no attestation). |
| `another deploy or teardown … is using this STATE_DIR` | Only one command runs per `STATE_DIR`; wait for the other, or stop it. A lock left by a process that is gone is taken over. |
| `STATE_DIR already holds deployment … in another project or region` | Tear that deployment down first, or use another `STATE_DIR`. |
| `TEARDOWN NOT COMPLETE` / `NOT CONFIRMED` | Read what remains or couldn't be listed, fix it (permissions, a resource in use), then run `scripts/teardown.sh` again. |
| A request is refused with `403` and a reason code | The body is the verifier's reason (for example `signature_missing`, `signature_invalid`, `governance_not_trusted`, `identity_inactive`). A plain `500` instead means the verifier didn't answer and the load balancer blocked the request. |

## Run it

```sh
make run
```

`make run` runs `make bootstrap` first (idempotent), then starts the request path above; it stays up until
`make clean`.

## Verify

```sh
make verify
```

It sends requests through the local edges and checks every answer, and Demo Bank's own records of what reached it
(`local/recipe.ts`, `verify`; the requests are made by `local/client.ts`, signing as each agent with its DNSid Local
key through the SDK). Expected output:

```
✓ unsigned request refused (signature_missing)
✓ alice.test signed GET allowed: Demo Bank's synthetic data, for alice.test under <governance>
✓ alice.test signed HEAD allowed
✓ tampered request refused (signature_invalid)
✓ forged x-dnsid-* headers replaced: Demo Bank saw the verified identity
✓ untrusted governance refused (governance_not_trusted)
✓ revoked bob.test refused (identity_inactive, identity_invalid or lifecycle_not_established)
✓ Demo Bank served exactly the three allowed requests, each for the verified identity
✓ nothing refused reached Demo Bank
✓ verify passed (DNSid Local and a local forwarding harness; this says nothing about Google's load balancer)
```

It exits nonzero on any miss, and then prints DNSid Local's container logs (lines that could carry a credential are
withheld). A revoked identity is refused by whichever check sees the revocation first: the identity's log evidence
(`identity_invalid`), its status document (`identity_inactive`), or the lifecycle check (`lifecycle_not_established`).

```sh
make clean
```

stops the request path and removes this mode's DNSid Local (its containers, network and volumes, through
`dnsid local reset --hard` on its own state directory) and its state directory. It is safe after a partial start or an
interruption, and to run twice. It refuses a state directory it didn't create, and never signals a process that isn't
its own request path.

What the local mode does not show: anything Google's load balancer does (how it forwards the request, its timeout,
its 500 when the verifier can't answer, its redirects), Cloud Run, or the authorization policy's coverage. The Google
Cloud deployment and its live tests check those.

### Troubleshooting (local)

| Symptom | What to do |
|---|---|
| `the dnsid CLI … could not be run` | Install it (see Prerequisites), or set `DNSID_CLI` to its path. |
| `Docker is not running` | Start Docker. |
| `dnsid local up` fails on a port | Another DNSid Local (or something else) holds 7753, 7755 or 443. Stop it (`dnsid local down`), or set `DNSID_LOCAL_DNS_PORT` and `DNSID_LOCAL_REGISTRY_PORT`; the HTTPS proxy must stay on 443. |
| `DNSid Local's DNS did not publish …` | Its DNS hadn't reloaded within 30 s; run `make bootstrap` again. |
| `… exists and was not created by this local mode` | `DNSID_GCP_LOCAL_HOME` points at a directory with other files; choose another. |
| `interrupted` | Run the same target again to resume, or `make clean`. |
| `verify failed` | Read the `got:` line under the failed check and the request path's records (`<state>/run/stack.jsonl`). |

## Testing

Local tests (no cloud, no credentials, no portal agents; nothing is built or deployed):

```sh
scripts/test-local.sh
```

They install the pinned dependencies (`npm ci`), type-check, run the unit and local acceptance tests, and validate the
infrastructure: `terraform fmt`, `terraform validate` against the locked providers' schemas with no backend, and
`terraform test` with mock providers. They also check the Cloud Build configuration, the Dockerfiles and the upload
allowlist statically; run `deploy.sh` and `teardown.sh` against simulated `gcloud` and `terraform` commands (a failure
after the bootstrap stage, during the build and partway through the service stage, then teardown, retries,
interruptions, unconfirmed removals); and run every live case against a local fixture edge (the real verifier and Demo
Bank behind a local HTTPS listener) and a simulated cloud, where each case is seen to pass and to fail.

They also run the local mode without Docker or the `dnsid` CLI: its request path (the local edge, the verifier with
the DNSid Local trust, Demo Bank) on offline test identities and on a DNSid Local look-alike (real DNS and HTTPS on
loopback, `tests/support/dnsid-local-lookalike.ts`, not DNSid Local itself), and `make bootstrap`/`run`/`verify`/`clean`
against simulated `dnsid` and `docker` commands, including failures, interruptions and what clean must leave alone.
`make verify` is the run against DNSid Local itself.

The container checks themselves need a container engine (`scripts/container-smoke.sh`); the deployment's image build
runs them.

Live tests, against a deployment (needs a DNSid agent, for example one registered in the Partner Preview Portal):

```sh
DEPLOY_OUT=<deploy-out.json> DNSID_AGENT_ID=<agent> DNSID_AGENT_KEY_FILE=<its private key> \
  OTHER_AGENT_ID=<another agent> scripts/test-live.sh
```

Every case, what it sends and what it expects: [docs/live-tests.md](docs/live-tests.md).

To send one request at a time and see what comes back (each step says whether it got what it expects; the key and the
signature are never printed):

```sh
DEPLOY_OUT=<deploy-out.json> DNSID_AGENT_ID=<agent> DNSID_AGENT_KEY_FILE=<its private key> \
  node scripts/live/request.ts signed      # or: unsigned, tampered, forged, claim <agent>, status <agent>, revoked
                                           # (revoked signs as DNSID_REVOKED_AGENT_ID with DNSID_REVOKED_AGENT_KEY_FILE)
```

- `MODE=live` (default) runs every live case of the acceptance criteria except `deny-revoked`; `MODE=allow` runs
  `allow-trusted` only; `MODE=revoked` runs `deny-revoked` only, against an agent that has already been revoked
  (nothing here revokes one). It passes only when the verifier refuses a freshly signed request with a revocation reason
  AND the source behind that reason, read by `test-live.sh` with the pinned SDK independently of the edge, identifies
  the revocation: for `identity_inactive` the agent's own DNSid status document reports `REVOKED`; for
  `identity_invalid` or `lifecycle_not_established` (the log already holds the revocation, so the verifier's log read
  refuses first) the agent's authenticated log history, verified under its accountable-entity key and the log's
  witnessed checkpoint, ends in a `REVOCATION`. The verifier's answer alone is not evidence: it is the same for a
  retired agent, a tampered log or one that can't be read. A timeout, an outage, another denial, `RETIRED` in either
  source, or evidence that can't be read or verified fails it.
- `LIVE_OUT` (default `live-out/` beside `DEPLOY_OUT`) receives `report.json`:
  `{"cases": [{"id", "edge", "expect", "got", "pass", "detail", "ms"}], …}`.
- The key file is a private JWK (as the DNSid CLI writes it) or a PKCS #8 PEM private key; it is never printed.
- `deny-untrusted-governance`, `deny-verifier-down`, `verification-timing` and `deny-forged-identity` change the
  deployment for a moment (the trusted governance list; the verifier's scaling; its log mode; Demo Bank's own `run.app`
  URL, opened to every caller) and put it back, which needs the same login as the deployment. Without one they fail and
  say so.
- `deny-forged-identity` (ADD-04) shows what Demo Bank does with a request that never went through the verifier, as
  when a front end forwards one without the authorization policy: it opens Demo Bank's `run.app` URL (ingress `all`,
  the default URL on), sends the agent's identity headers without an attestation (Demo Bank's 403
  `identity_attestation_required`) and with a forged one (403 `identity_attestation_invalid`), then closes the URL
  again (ingress internal and Cloud Load Balancing, the default URL off) and confirms it in Demo Bank's configuration
  and by the URL serving nothing.
- The EDGE-02 denials and `deny-verifier-down` also need Demo Bank's own request log to show nothing reached Demo Bank
  in their windows; that needs the login too, and without it they fail. After every other case one more signed request
  is sent as a control; the windows are judged only once the log shows that request, waiting up to two minutes for a
  slow log (`LIVE_LOG_WAIT_S`, default 120).
- `evidence-freshness` (EDGE-06) and `verification-timing` (ADD-05) are judged from the verifier's own record of each
  request it let through: the elapsed time from accepting the request to deciding (within the 2,500 ms budget), how the
  log evidence's completeness was established (`trusted-index`, a signed stream bundle, or `full-scan`), whether the
  identity material came from the verifier's cache (`hit`, `miss` for a cold verification, `partial`), and the
  evidence age (at most 300 s). Each served request must have exactly one complete record; the records are waited for
  up to `LIVE_LOG_WAIT_S`, and missing, extra or incomplete records fail the case. `verification-timing` measures five
  requests as deployed, then sets `DNSID_LOG_EVIDENCE=full-scan` on the verifier (a new revision: no stream bundle is
  read, every lifecycle read is the complete raw scan of the log the SDK falls back to, verified against the witnessed
  checkpoint). Every request from then on is in a window whose records are read, so the new revision's first
  verification is among them: it must be a cold `miss` (nothing reused) within the budget, never a warmed `hit` or
  `partial`. Three more records must say `full-scan`; then the setting is removed.
- Every `gcloud` command the live tests run is bounded (five minutes) and killed past it; a killed command is waited
  for until it has stopped, so it can't take effect after the restoration. Before a case changes the deployment it
  records the change in `LIVE_OUT/pending-restore.json`. The record is removed only once the restoration is confirmed:
  the restoring update succeeded, the changed service's configuration (`gcloud run services describe`) reads back as
  restored before and after the edge is checked, and the edge behaves as before. A setting that reads back changed again gets
  the restoring update once more. Ctrl-C or SIGTERM stops the run, still restores and confirms a change in progress,
  writes the report (the cases not reached marked "not run") and exits 130; a second signal exits at once and leaves
  the record. The next `test-live.sh` restores a recorded change, confirmed in the verifier's configuration, before
  anything else, and stops with exit 4 if it can't (no login, the update fails, or it doesn't read back). If a
  restoration fails or can't be confirmed during a run, or a killed change command doesn't stop (its effect is then
  unknown), the record is kept, no further change is made and `test-live.sh` exits 4: run it again to restore the
  setting, tear down or deploy again.

## Security model and known limitations

- **What a 403 means.** Every verification denial is the verifier's 403 with a reason code. When the verifier can't
  answer (an outage, or a timeout past 3,000 ms), the load balancer blocks the request with its own generic 500
  (`fail_open = false`). Neither reaches Demo Bank.
- **Identity headers.** The verifier removes every caller-supplied `x-dnsid-*` header and sets
  `x-dnsid-verified-domain`, `x-dnsid-governance-id` and `x-dnsid-attestation`: an HMAC-SHA256 over the two values and
  the time, under a key Terraform generates for each deployment (`random_password`) and gives to the verifier and Demo
  Bank only, as `DNSID_ATTESTATION_KEY`. Demo Bank accepts the identity only with a valid attestation at most 30 s old;
  without one it refuses with 403 (`identity_attestation_required`, `identity_attestation_invalid` or
  `identity_attestation_stale`). Their presence alone authenticates nothing. What else keeps other callers out is the
  deployment: ingress limited to internal and Cloud Load Balancing traffic, the default `run.app` URLs disabled, and
  the authorization policy on the only forwarding rule. The key is a Cloud Run environment variable, so anyone in the
  project who can read the services' configuration (`run.services.get`) can read it; it is also in the service stage's
  Terraform state in `STATE_DIR`. It lives only as long as the deployment.
- **The authorization policy takes effect gradually.** On the eighth live deployment (2026-11-14), about 12 minutes
  after the policy was created, and after the readiness wait had passed, one of Google's front ends forwarded a signed
  request to Demo Bank without evaluating the policy: the load balancer logged no `authzPolicyInfo` for it, the
  verifier never saw it, and Demo Bank refused it only because it carried no identity headers. A caller sending forged
  identity headers in that window would have been served as that identity before the attestation. The attestation is
  what keeps that window closed: Demo Bank refuses such a request whatever headers it carries. Readiness waits for the
  policy to hold (step 5) so that the live tests and a reader's first requests don't meet the window, but no wait can
  prove it is over. This is an open risk for any deployment whose origin trusts headers from the edge.
- **DNSid identifies; Demo Bank authorizes.** The edge decides which organizations' agents may reach Demo Bank at all
  (the trusted governance IDs); Demo Bank decides what each verified agent may read, from its own mapping of verified
  domains to synthetic accounts (each agent its own two, derived from its domain, so nothing is configured). Another
  agent's account is refused with 403 `account_not_permitted` by Demo Bank, whatever governance vouched for the caller.
  A real API keeps its own authorization in the same place.
- **Replay** of a captured request within the signature's 300-second window is accepted (Demo Bank is read-only); it
  needs a nonce store to prevent.
- **Bodies.** An authorization extension sees headers, never content, so only `GET` and `HEAD` without content are
  allowed. On the live deployment, Google's front end itself refused every `GET` or `HEAD` that carried content with
  its own `400`, before the extension ran; the verifier's own check (`body_indicated`, `body_not_ruled_out`) stays as
  the second line.
- **Paths as the load balancer forwards them.** On the live deployment, a path with a percent-encoded unreserved
  character (`/%61ccounts`) reached the verifier decoded (`/accounts`), so a signature over the escaped form was
  refused (`signature_invalid`). Demo Bank gets the same path the verifier checked. Sign the path in its normalized
  form: unreserved characters (letters, digits, `-`, `.`, `_`, `~`) unescaped. Other escapes (`%20`, and in the query)
  arrive as sent.
- **Checkpoints** of the DNSid log are kept in each verifier instance's memory: no protection against a log rollback
  across a restart.
- **Internal ingress** admits traffic from the project's own VPC; a project that runs other workloads must close that.
- **Unauthenticated invocation.** Google requires a callout's Cloud Run service to allow unauthenticated invocation, and
  the load balancer presents no identity to Demo Bank; both services disable the invoker IAM check instead of granting
  `allUsers`, and rely on ingress and the disabled default URLs.
- **The self-signed certificate** is for a quick start; a production deployment uses a managed certificate on a name.
- **Revocation** takes effect without a redeploy or a configuration change; how long it takes depends on the registry,
  the hosted status document's cache, the log and its witnesses. One observation (2026-11-16), never a guarantee: on one
  unchanged deployment, with no redeploy, the disposable agent was allowed at the edge at 06:59:30Z, revoked in the
  Partner Preview Portal at 17:11:53Z (the operator's reading of the portal's own time) and refused at the edge by
  17:13:11Z. The refusal was observed within about 80 seconds of the portal action; the run did not poll continuously,
  so the moment refusal began is not known and no propagation bound is established.

## What is not verified yet

The latest live run on 2026-11-16 (see Status) established the image build and its container checks in Cloud Build, both
Terraform stages, readiness, all 30 live cases (request fidelity, the end-of-stream indication, the `..` redirect, the
closed bypass routes, the 500 when the verifier can't answer, the governance change, the attestation through the load
balancer and Demo Bank's own refusal of forged identity headers, the verifier's records, including a cold full-scan
verification of 1,987 ms), the refusal of an already revoked agent and the teardown. The same image-build source was
deployed, tested and torn down on 2026-11-14 as well, so two complete cycles have run. Not established by them:

- that the authorization policy is in force on every front end: Google applies it gradually, the readiness wait only
  makes meeting the window unlikely, and the attestation is what keeps a request that skips it from being served;
- the Application Default Credentials login (`gcloud auth application-default login`): every live run logged in with
  a short-lived access token;
- how long a revocation takes to show: the disposable agent was recorded as allowed before revocation; on the latest
  deployment a freshly signed request was later refused with `identity_inactive`, and the independently read status
  document reported `REVOKED` (the independent log-history lookup timed out). One observation (2026-11-16), never a
  guarantee: on one unchanged deployment, with no redeploy, the disposable agent was allowed at the edge at 06:59:30Z,
  revoked in the Partner Preview Portal at 17:11:53Z (the operator's reading of the portal's own time) and refused at
  the edge by 17:13:11Z. The refusal was observed within about 80 seconds of the portal action; the run did not poll
  continuously, so the moment refusal began is not known and no propagation bound is established. Nor does it establish
  continuous success of an active control throughout the transition;
- teardown after a real partial deployment at each step (bootstrap, images, service), with the project's resources
  listed before and after: the scripts handle it and the tests simulate it, but it has not been interrupted live on
  purpose; and a complete teardown inventory: the latest teardown could not list the project's IAM bindings (the
  deployment creates repository and bucket grants, not project-level ones) and says so;
- `make verify` against DNSid Local (it needs Docker and the `dnsid` CLI).

## What to try next

- **Watch revocation happen.** After `make verify`, revoke `alice.test` the way bootstrap revoked `bob.test` (Step 1)
  and run `make verify` again: its `alice.test` checks now fail, because the edge refuses the revoked identity, and
  nothing was restarted or reconfigured.
- **Trust your own organization.** Deploy with `DNSID_TRUSTED_GOVERNANCE` set to your governance ID and sign with one of
  your agents (`scripts/test-live.sh` shows how).
- [Recipe 32](../32-cloudflare-workers/) does the same verification at the Cloudflare edge;
  [recipe 06b](../06b-go-http-stripe/) inside an API server instead of in front of it.
- `make clean && make verify` — watch the full first run instead of the idempotent path.

## Glossary

- **Authorization policy (`CUSTOM`)** — the Google Cloud resource that attaches an authorization extension to a load
  balancer's forwarding rule, so requests through that rule are asked about once it is in force (it takes effect
  gradually; see the security model).
- **Continuation** — the verifier's "let it through" answer to the load balancer, with the headers to remove and set.
- **Demo Bank** — the sample API behind the edge, with synthetic data. It maps each verified domain to its own synthetic
  accounts and refuses any other: a verified identity says who the agent is, and Demo Bank decides what it may read.
- **ext_proc** — Envoy's external processing protocol: a gRPC stream on which the proxy sends request headers and the
  service answers what to do with them.
- **Reason code** — the body of a 403: `signature_missing`, `signature_invalid`, `governance_not_trusted`,
  `identity_inactive`, `identity_invalid`, `lifecycle_not_established` and the others each stage defines
  (`src/preconditions.ts`, `src/signature.ts`, `src/identity.ts`, `src/lifecycle.ts`, `src/response.ts`).

## Layout

| Path | What |
|---|---|
| `src/` | The verifier (ext_proc gRPC service). |
| `local/`, `Makefile` | The local mode: DNSid Local trust, the local edge, the request path, its client and `make bootstrap`/`run`/`verify`/`clean`. |
| `origin/` | Demo Bank, the protected sample API. |
| `proto/` | Envoy's ext_proc schemas, vendored. |
| `infra/bootstrap`, `infra/service` | The two Terraform stages, with provider locks and `terraform test` files. |
| `cloudbuild.yaml` | The image build and its checks. |
| `scripts/deploy.sh`, `scripts/teardown.sh` | One command up, one command down. |
| `scripts/test-live.sh`, `scripts/live/` | The live tests, and `request.ts` for single requests. |
| `scripts/test-local.sh` | The local tests. |
| `scripts/container-smoke.sh` | The container checks (run by the image build, or locally with Docker). |
| `scripts/lib/` | Shared helpers: authentication and state, the upload allowlist, DEPLOY_OUT, pinned TLS, the inventory checks. |
| `tests/` | Unit and local tests, fixtures and test-only support. |
| `docs/live-tests.md` | The live cases: what each sends and expects. |

## License

Apache-2.0 (`LICENSE`).
