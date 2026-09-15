# A2A and LangGraph testnet recipes plan

Status: planning artifact

This plan covers two coupled cookbook recipes and the harness they share:

- **Recipe 12 — A2A protocol + DNSid** ⭐ (slot already reserved in `INDEX.md`): the
  existing `dnsid-py/examples/a2a` / `dnsid-ts/examples/a2a` walkthrough, promoted to
  its canonical narrative home in the cookbook.
- **Recipe 31 — LangGraph agent with a DNSid identity**: a LangGraph agent that *is* a
  verifiable A2A endpoint (ingress), *makes* RFC 9421-signed HTTP tool calls (egress),
  and gates a sensitive tool on the verified caller (authorization).
- **The cookbook's single harness** (`testnet-cli`, the real DNSid testnet driven by
  the `dnsid` CLI). Decision: the cookbook has exactly one harness, and it uses DNSid —
  the CoreDNS + mock-registry convention is retired, not kept as a second tier.

## Why these are one plan

Recipe 31 builds directly on recipe 12's ingress path and on the same testnet harness.
Deciding the harness twice, or letting the two recipes duplicate divergent copies of the
same middleware, is the failure mode this plan exists to prevent.

## Source material (three places, none of them new code)

| Source | What it contributes | What it does not contribute |
|---|---|---|
| `dnsid-py/examples/a2a` (+ TS mirror) | The whole recipe-12 body: agent card with DNSid extension, ASGI signature middleware, signed A2A client, testnet lifecycle, C2SP issuance flow | Cookbook-style progressive narrative |
| `dnsid-partner-plugins` (`_shared/python/dnsid_agent_identity`) | The recipe-31 egress core: `HttpSig9421Auth` (an `httpx.Auth` that signs every method sync/async and re-signs on redirects) and `IdentityBundle`/`load_identity` | The MCP seam and LangGraph MCP adapter (recipe 31's egress is plain signed HTTP — see below; the seam is a "What to try next" pointer); the offline in-memory registry as a featured path (unit-test scaffolding only); the other five framework adapters; its stale `dnsid-testnet` references |
| Cookbook conventions (`RECIPE_TEMPLATE.md`, `Makefile`, `scripts/`) | README structure, `make run` / `make verify` contract, hardcoded-identity scanner | A scaffold for this harness (`make new` assumes CoreDNS + compose and gets rewritten — see below) |

The partner-plugins code was written 2026-07-09 and has sat unexercised since.
Vendored code must be re-tested against current `dnsid-py` and `httpx`, not trusted.
Talk to its author before repurposing.

## The harness: `testnet-cli` (the only one)

The cookbook standardizes on a single harness: the real DNSid testnet, driven by the
`dnsid` CLI. The existing CoreDNS convention (fixed IP `172.20.0.2`, `zones/test.zone`,
the `mocks/dnsid-registry/` sidecar the template describes) is retired. A mock harness
can teach the record format, but it cannot teach first-contact trust — the demo itself
provisions the keys the verifier then finds — and maintaining two harnesses means every
future recipe re-decides which one to use and every shared fixture exists twice.

The retirement is cheap: an audit of `recipes/` shows **only recipe 01** references
`mocks/dns` / CoreDNS, `mocks/` contains only `dns`, and the `mocks/dnsid-registry/`
sidecar the template mandates was never actually built. Record-format teaching survives
the move — under the testnet the reader inspects the real record with
`dig @$DNSID_DNS_SERVER _dnsid.<domain> TXT` instead of opening a zone file, which is
truer to how DNSid behaves in the wild anyway.

The `testnet-cli` harness:

- **Prerequisites:** Docker 24+, `make`, the `dnsid` CLI (from `dnsid-ai/dnsid`),
  Python 3.11+ (recipes use `uv`). No Node required for the default path.
- **Lifecycle:** `dnsid testnet up` / `down` / `reset --hard`; identities via
  `dnsid testnet agent ensure <name> --upstream <url> -- dnsid log issue --domain <fqdn>`;
  processes launched under `dnsid testnet run <name> -- <cmd>`, which injects the full
  `DNSID_*` environment (DNS routing, CA bundle, registry credential, independently
  trusted `DNSID_LOG_POLICY_URL`, identity directory).
- **Image:** `ghcr.io/identity-digital/dnsid-testnet-registry:main` — confirmed
  anonymously pullable, so CI needs no token for it.
- **What it proves that a mock cannot:** registration → challenge → publish
  lifecycle, DNS-delivered trust on first contact, live status, and operationally
  countersigned C2SP ISSUANCE entries.
- **Policy trust rule (normative, from the 2026-08-24 SDK fix wave):** the C2SP policy
  URL comes only from the independently supplied `DNSID_LOG_POLICY_URL`. Never derive it
  from `DNSID_LOG_REF` or any log-provided data.

Because this is the only harness, the convention docs change with it:

- **`RECIPE_TEMPLATE.md`**: the "DNS infrastructure", CoreDNS-gotchas, and
  mock-registry author notes are *replaced* (not supplemented) by testnet-cli
  instructions — lifecycle commands, the `DNSID_*` environment contract, and the
  policy-trust rule above. The "Docker stack" section becomes a "Running system"
  section (the testnet's containers are CLI-managed, not recipe-owned compose files).
- **`scripts/new-recipe.sh` (`make new`)**: rewritten to scaffold a testnet-cli recipe
  (Makefile with `bootstrap`/`run`/`verify`/`clean`, `pyproject.toml`, `src/`,
  `verify/verify.sh`) instead of zone file + docker-compose. Recipe 12's Makefile is
  written by hand first; the scaffold generalizes it once recipe 31 confirms the shape.
- **Recipe 01 migrates** to the testnet harness (its zone-file/JWKS teaching becomes
  `dig`/`curl` against the live testnet), and **`mocks/dns` is deleted** once nothing
  references it. Sequenced below; the two new recipes do not block on it.

## Recipe 12 — A2A protocol + DNSid ⭐

Tagline (already in `INDEX.md`): two A2A agents from different organizations begin a
session on first contact, with no shared API keys, no manual key exchange, and no
out-of-band introduction.

```
recipes/12-a2a-dnsid/
  README.md            # template structure; harness: testnet-cli
  Makefile             # bootstrap / run / verify / clean
  pyproject.toml       # deps: dnsid-py, a2a-sdk, fastapi, uvicorn, dnspython
  src/
    agent_card.py      # AgentCard with the DNSid HTTP-signature extension declaration
    middleware.py      # ASGI ingress: verify RFC 9421 + A2A version/extension headers
    server.py          # FastAPI + a2a-sdk routes, JWKS + status well-knowns
    client.py          # signed A2A client (create_signed_async_http_client)
    executor.py        # echo AgentExecutor reading the verified sender
    main.py            # Alice/Bob entry point (mirrors examples/a2a/main.py)
  verify/
    verify.sh          # one-shot: full flow, asserts expected transcript
```

Step narrative (from the existing example's "How it works" table, expanded to template
form): identity load from `DNSID_*` env → registration → challenge signature →
`publish_to_registry` → self-`verify_domain` → signed send → verified receive → echo
with verified sender. Plus one **anti-pattern subsection**: what breaks when the policy
URL is derived from the log reference, and what an unsigned request's 401 looks like.

`make` targets:

- `make bootstrap` — `dnsid testnet up` + `agent ensure` alice and bob + `log issue` both
- `make run` — Bob under `dnsid testnet run bob`, then Alice sends one message
- `make verify` — scripted run asserting: identity published (or `already published
  (READY)`), signature verified line on Bob, reply text containing both verified
  identities; exits nonzero otherwise
- `make clean` — `dnsid testnet down`

Language scope: **Python in `src/`, single toolchain.** The TS mirror stays in
`dnsid-ts/examples/a2a` (its `test/a2a-testnet-config.test.ts` imports it; it is a CI
fixture). The README's "What to try next" points at running TS Bob against Python Alice
for the cross-language proof. Open question: vendor a TS agent into the recipe later if
readers ask for it side by side.

### What happens to the SDK examples

Copy first, thin second:

1. Recipe 12 lands; SDK repos untouched; CI stays green everywhere.
2. Follow-up PR per SDK repo thins `examples/a2a` READMEs to a pointer at recipe 12
   plus SDK-specific notes, keeping the code that CI imports (`testnet_config.py`,
   `testnet-config.ts`, and enough agent code to remain a working interop fixture for
   `dnsid-sdk-compliance`).
3. Only then delete duplicated tutorial prose. No red-build window, and the pre-1.0
   "replace, don't preserve" rule is satisfied at the end state, not mid-flight.

## Recipe 31 — LangGraph agent with a DNSid identity

What the reader builds: a LangGraph agent, addressable as an A2A endpoint, whose
inbound calls are DNSid-verified, whose outbound HTTP tool calls are RFC 9421-signed and
attributable to the agent's domain, and whose sensitive tools exist only for verified
callers on an allowlist. Three identities on one testnet: `graph.dev.dnsid.test` (the
LangGraph agent), `tools.dev.dnsid.test` (a plain HTTP tool API that verifies its
callers), `peer.dev.dnsid.test` (the A2A caller driving the demo).

Egress is a **plain signed-HTTP tool, not MCP**. MCP was the partner-plugins repo's
constraint (one seam shared by six frameworks), not DNSid's: RFC 9421 signing is
protocol-agnostic HTTP, so the trust story is identical over a plain `@tool` whose
httpx client carries the signing auth. Dropping MCP removes the plan's riskiest
dependency cluster (`mcp` mid-rename, `langchain-mcp-adapters` drift, `_mcp_compat`),
keeps the recipe's concept count down (LangGraph + DNSid + A2A is already three
domains), and lets the tool server reuse recipe 12's middleware verbatim — the reader
sees the *same* verification pattern on graph-ingress and tools-ingress. MCP × DNSid
coverage already lives in recipes 7/7b/8; the MCP client seam (partner-plugins'
`mcp_factory`) is referenced in "What to try next" for readers whose tools arrive
via MCP.

```
recipes/31-langgraph-dnsid-agent/
  README.md            # harness: testnet-cli; builds on recipe 12
  Makefile             # bootstrap / run / verify / clean (three identities)
  pyproject.toml       # + langgraph (no mcp / langchain-mcp-adapters deps)
  src/
    dnsid_identity/    # vendored egress core from dnsid-partner-plugins (attributed):
      auth.py          #   HttpSig9421Auth (httpx.Auth)
      identity.py      #   IdentityBundle + load_identity(source="env")
    middleware.py      # verification middleware — same as recipe 12 (see "shared code");
                       #   used by BOTH the A2A ingress and tools_server
    graph.py           # the LangGraph graph: model node + ToolNode; caller-gated tools;
                       #   tools call tools_server via one shared signed httpx client
    executor.py        # A2A AgentExecutor -> graph.ainvoke(...)
    tools_server.py    # FastAPI app for tools.dev.dnsid.test; verifies inbound 9421
    main.py
  verify/verify.sh
```

The demo runs **without an LLM key by default**: the graph's model node uses a
deterministic scripted chat model that always calls the tool, so `make verify` is
reproducible in CI. Setting `ANTHROPIC_API_KEY` swaps in a real model (default model id
in one place; use a current Claude model and re-check the id at implementation time
rather than trusting this plan). The LLM is never in the trust path either way: it
chooses tool arguments; identity, verification, and the tool allowlist are code.

### Security invariants (normative for the recipe and its README)

1. **The verified caller lives in `config["configurable"]`, never in graph state.**
   Graph state is writable by node return values, which are downstream of model output;
   a state-carried identity is a prompt-injection-to-authorization-bypass path. The A2A
   executor sets `configurable: {"dnsid_caller": <verified domain>, "thread_id": ...}`
   at invoke time; nodes read it, nothing writes it.
2. **Tool exposure is computed from the verified caller before the model runs.** The
   sensitive tool is absent from the bound tool set for non-allowlisted callers — not
   merely refused when called.
3. **A resumed checkpoint inherits no trust.** Every inbound A2A call is re-verified;
   `thread_id` is derived from the verified caller domain so one caller cannot resume
   another's thread. Signature freshness (300 s default) makes stored identity stale by
   construction.
4. **Egress signs the exact bytes sent** (`requires_request_body` on the auth), and the
   tool server verifies with required covered components including `content-digest`.
5. **One signed client, injected — never constructed per tool.** Plain-HTTP egress has
   no transport-level choke point, so the signed httpx client is built once and handed
   to every tool; a tool that builds its own `httpx.Client` ships unsigned traffic
   silently. The README names this as an anti-pattern (it is the honest argument for
   the MCP-factory seam in production systems with many tools).

### Step narrative

1. Concepts: what LangGraph adds (graph, tools, config vs state) — one screen, template
   progressive-style.
2. Identity from environment (`load_identity(source="env")` under `dnsid testnet run`).
3. Egress: one shared httpx client carrying `HttpSig9421Auth`, injected into the tool
   bodies; show the verified-caller log line on `tools.dev.dnsid.test`.
4. Ingress: recipe-12 middleware in front of the A2A routes; executor threads the
   verified caller into `configurable`.
5. Authorization: the caller-gated tool set; demonstrate allowlisted vs non-allowlisted
   caller.
6. Run + verify.
7. Anti-patterns: identity in graph state (show why), trusting a resumed checkpoint,
   deriving policy trust from log data, per-tool client construction (invariant 5).
8. What to try next: tools arriving via MCP — the partner-plugins `mcp_factory` seam
   signs at the MCP client's `httpx_client_factory` choke point; recipes 7/7b/8 for
   MCP × DNSid at the gateway.

`make verify` asserts the full chain in one transcript: peer→graph ingress verified,
graph→tools egress verified as `graph.dev.dnsid.test`, reply carries both identities,
and a second call from a non-allowlisted identity shows the sensitive tool absent.

## Shared code between 12 and 31

The ingress middleware and agent-card builder appear in both recipes. Near-term: copy
into each recipe's `src/` (each recipe must run standalone per the template; the files
are ~150 lines and stable). The copy is a signal, not a solution: the durable home for
the ASGI verification middleware is `dnsid-py` itself, as an application-profile helper
next to `HttpSignatureProfile` (it is already copy-pasted between the a2a example and
`dnsid-partner-plugins/_shared/.../verifier.py`, and these recipes make copies three and
four). File that as a `dnsid-py` issue when recipe 12 lands; both recipes then shrink.

## Sequencing

| PR | Repo | Content |
|---|---|---|
| 0 | dnsid-cookbook | CI workflow: per-recipe `make verify` job (matrix); every job installs the `dnsid` CLI and pulls the testnet image. Without this, a flagship recipe ships ungated and rots. |
| 1 | dnsid-cookbook | `RECIPE_TEMPLATE.md` rewritten for the testnet-cli harness + recipe 12 + `INDEX.md` update |
| 2 | dnsid-cookbook | Recipe 31 (+ `INDEX.md`: new entry and a LangGraph standards-map row; RFC 9421 row gains 31) |
| 3 | dnsid-cookbook | Migrate recipe 01 to the testnet harness; rewrite `scripts/new-recipe.sh`; delete `mocks/dns` |
| 4 | dnsid-py / dnsid-ts | Thin `examples/a2a` to fixture + pointer (one PR each, after 1) |
| 5 | dnsid-py | Issue (not PR): promote ingress middleware into the SDK |

Recipe 31 does not block on 3–5. Until PR 3 lands, recipe 01 keeps working on its
CoreDNS setup — a transitional inconsistency, accepted because the alternative
(blocking the new recipes on a migration) is worse. The rule from PR 1 onward: **no new
recipe uses mocks or CoreDNS.**

## Acceptance

- Clean clone + prerequisites → `make bootstrap && make run && make verify` green for
  both recipes, locally and in cookbook CI.
- `make verify` re-run without reset shows the idempotent path (`already published
  (READY)`), matching the a2a example's documented behavior.
- `scripts/scan-hardcoded-identities.py` passes; all domains are `*.dev.dnsid.test`.
- End state (after PR 3): no recipe, template section, or script references CoreDNS,
  `zones/`, or `mocks/` — one harness, grep-verifiable.
- `INDEX.md` recipe-12 entry keeps its existing tagline; recipe 31 added with an
  affirmative "Why this matters" that names what changes (an agent framework's tool
  calls become attributable to a domain; the tool server needs no API-key onboarding).
- Vendored `dnsid_identity/` code (`auth.py`, `identity.py`) re-verified against
  current `dnsid-py` and `httpx` at implementation time; pins recorded in the recipe's
  `pyproject.toml`, not inherited from the July snapshot.

## Gaps and risks

- **Cookbook has no CI today.** PR 0 is the mitigation; the risk if skipped is a
  flagship recipe whose `make verify` silently rots (the template forbids exactly this).
- **`langgraph` API drift.** With MCP out of the egress path, the remaining
  fast-moving dependency is LangGraph itself (state/config APIs, `create_react_agent`
  vs `create_agent` era); pin what the recipe tests against and record the version in
  the README's prerequisites. (The `mcp` / `langchain-mcp-adapters` drift risk moved
  out of scope with the plain-HTTP egress decision; it returns only if the MCP
  "What to try next" pointer is ever promoted to a step.)
- **Testnet-in-CI is more moving parts** than a one-shot verifier container (Docker-in-
  runner, container startup ordering, CLI install). Recipe 12's verify script should
  emit the testnet logs on failure or debugging CI will be painful.
- **Python 3.11+ prerequisite** is new for the cookbook; document `uv` usage in both
  READMEs (the partner-plugins demos already model this).
- **Heavier floor for the simplest recipe.** Single-harness means even recipe 01
  requires the `dnsid` CLI, not just Docker + make. Accepted deliberately: one honest
  harness over two divergent ones. The mitigation is a good "Prerequisites" block and
  a `make bootstrap` that gets a cold reader to a running testnet in one command.
- **Recipe 01 migration fidelity.** Its current value is hand-inspecting the record and
  JWKS; the migrated version must keep that tactile quality (`dig` the TXT, `curl` the
  JWKS from the live testnet) rather than becoming a lifecycle demo — that's recipe
  12's job.
- **`dnsid-partner-plugins` disposition** (archive? README pointer at recipe 31? keep
  the other five adapters?) is deliberately out of scope here — decide after recipe 31
  proves the pattern. Consult the original author before vendoring.
- **Revocation beat** (revoke `peer` mid-session, next call denied) would strengthen
  recipe 31 but depends on testnet CLI revocation support — stretch goal, verify CLI
  capability first.
