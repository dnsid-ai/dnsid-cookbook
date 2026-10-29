# Recipe 31 — LangGraph agent with a DNSid identity

> A LangGraph agent that verifies who calls it, signs every request it makes, refuses to call peers it can't verify, and exposes its sensitive tool only to allowlisted callers — from one small, reusable module.

**Spec version:** `dnsid-draft-01`
**Status:** runnable
**Standards used:** RFC 9421 (HTTP Message Signatures), RFC 7517 (JWKS), C2SP tlog (transparency log); framework: LangChain 1.4 `create_agent` on LangGraph 1.2
**Estimated time:** ~20 minutes

---

## What you'll build

A LangGraph agent called `graph.test` that takes orders. It can do four things a normal agent can't:

| The agent… | So that… | Module piece |
|---|---|---|
| **verifies who's calling it** | only callers with a valid DNSid identity get in | `DnsidAuthMiddleware` |
| **signs everything it sends** | the services it calls know it's really `graph.test` | `dnsid_client` |
| **verifies whom it calls** | it can't be talked into calling an unknown host | `dnsid_client` |
| **gives each caller only its own tools** | `place_order` exists only for allowlisted callers | `DnsidToolPolicyMiddleware` |

All four come from [`langchain-dnsid`](lib/langchain-dnsid/), a small package in `lib/` (about 300 lines, many of them comments) that you can reuse in your own agents. [Add DNSid to your own agent](#add-dnsid-to-your-own-agent) shows how.

Here's who's involved:

```
   peer.test ──┐                        ┌──> tools.test   (has an identity: request sent)
               ├──> graph.test (agent) ─┤
outsider.test ─┘                        └──> rogue.test   (no identity: refused, nothing sent)
```

- `peer.test` is on the allowlist, so it can place an order.
- `outsider.test` has a valid identity but isn't on the allowlist, so it never sees `place_order`.
- `rogue.test` has no identity, so the agent refuses to contact it.

The agent runs on a real model from any provider LangChain supports; you pick it in step 1.

## Why this matters

LangGraph handles the agent loop, but not identity. Without something like DNSid:

- the agent's outbound calls carry API keys someone had to issue and share,
- anyone who knows its URL can call it,
- a prompt can steer the model into calling any URL.

DNSid replaces all three with one mechanism: each party proves who it is with a signature that anyone can check through DNS. After this recipe, the tools API knows which agent sent each request without issuing it a credential. The agent decides who may order based on a verified identity, not on anything in the prompt.

## Prerequisites

- Docker 24+ (running)
- `make`
- The `dnsid` CLI — `brew install dnsid-ai/tap/dnsid`, or download a binary per the [installation docs](https://docs.dnsid.ai/cli-installation) and put it on `PATH`
- [`uv`](https://docs.astral.sh/uv/) 0.12+ (it installs Python 3.11+ for you)
- A clone of this repo
- An API key for a model provider that supports tool calling (Anthropic, OpenAI, Google, …)

Tested with dnsid-py v0.32.0, langchain 1.4.3, langgraph 1.2.12, Python 3.13. All versions are pinned in [`pyproject.toml`](pyproject.toml).

## Concepts

Four ideas carry the whole recipe:

- **DNSid identity** — a domain that has published its public keys through DNS. To check a domain, a verifier:
  1. looks up its `_dnsid.<domain>` DNS record,
  2. fetches the public keys the record points to,
  3. confirms the identity is still active.

  No certificate authority (CA) and no shared secret is involved.
- **Signed requests (RFC 9421)** — a standard way to sign an HTTP request. The signature locks the method, URL, and body, so nothing can be changed in transit without breaking it.
- **`create_agent` middleware** — LangChain's standard LangGraph agent takes *middleware*: code that runs around every model call and every tool call. It's the closest LangGraph has to a plugin.
- **Runtime context** — data your code passes into a run with `context=`. The model can't change it, and it isn't saved between runs. That makes it the safe place to put "who is asking."

Everything runs on **the DNSid local registry**: a complete DNSid setup (DNS, registry, transparency log, HTTPS proxy) that the `dnsid` CLI runs in Docker on your machine.

## Running system

| Process | Where | Role |
|---|---|---|
| Local registry | Docker containers (`dnsid local up`) | DNS on `127.0.0.1:7753`, registry on `:7755`, HTTPS proxy on `:443` for every `https://<name>.test` |
| Graph agent | host process, `:3101` | The LangGraph agent, `graph.test` |
| Tools API | host process, `:3103` | A plain HTTP API, `tools.test`: `GET /catalog`, `POST /order` |
| Peer, outsider | short-lived host processes | Each sends one request to the agent, then exits |

## Step 1 — Pick a model and create the identities

Install your provider's LangChain package, set its API key, and name the model as LangChain's `provider:model` string:

```bash
uv pip install langchain-anthropic          # or langchain-openai, langchain-google-genai, ...
export ANTHROPIC_API_KEY=...
export DNSID_RECIPE_MODEL=anthropic:claude-sonnet-5
```

Then start the local registry:

```bash
make bootstrap
```

This starts the local registry and creates four identities: `graph`, `tools`, `peer`, and `outsider`. Each one gets a key pair and a published DNS record. Look at one:

```bash
dig @127.0.0.1 -p 7753 _dnsid.graph.test TXT +short
```

That's the entire trust setup. No API keys, and nothing exchanged between any two parties.

Each process loads its identity with one line ([`src/main.py`](src/main.py)), using environment variables that `dnsid local run` provides:

```python
    idm = identity_manager_from_environment()
```

## Step 2 — Check every incoming request

Both servers are ordinary FastAPI apps. Each is wrapped in one middleware:

```python
    return DnsidAuthMiddleware(app, idm)
```

For each incoming request, [`DnsidAuthMiddleware`](lib/langchain-dnsid/src/langchain_dnsid/ingress.py) does one of three things:

- **No signature, or one that doesn't verify:** it rejects the request with a 401 before your code runs.
- **The same signed request again** (someone captured and resent it): it rejects that with a 401 too. Each signature works once.
- **Valid signature:** it passes the request on, with the sender's verified domain in `request.state.dnsid_caller`. Only the middleware sets that value; a client can't fake it.

The middleware only tells you *who* is calling. What they may do is up to your routes. The tools API takes orders from the agent and no one else:

```python
        if request.state.dnsid_caller != ORDERING_AGENT:
            raise HTTPException(403, f"only {ORDERING_AGENT} may place orders")
```

## Step 3 — Sign and check every outgoing request

The agent sends everything through one HTTP client:

```python
    agent = build_agent(dnsid_client(idm), TOOLS_URL)
```

Before each request, [`dnsid_client`](lib/langchain-dnsid/src/langchain_dnsid/egress.py) does two things:

1. **Checks the destination.** Is it HTTPS, and is the host a live DNSid identity? If not, it refuses, and nothing is sent. (A signature proves who sent a request; only HTTPS protects the reply.)
2. **Signs the request as this agent**, so the receiver can verify who sent it.

The callers use the same client, which is how `peer.test` checks that it's really talking to `graph.test`.

> **Rule:** build one `dnsid_client` and hand it to every tool. A tool that creates its own `httpx` client sends unsigned, unchecked requests, and nothing in LangGraph will warn you.

`dnsid_client` refuses any host without a DNSid identity, on purpose. For ordinary third-party APIs, use a separate, plain client.

## Step 4 — Give each caller only its tools

[`src/graph.py`](src/graph.py) is a standard `create_agent` with one middleware added:

```python
    return create_agent(
        # Any LangChain model, as "provider:model", e.g. "anthropic:claude-sonnet-5".
        model=os.environ["DNSID_RECIPE_MODEL"],
        tools=[place_order, fetch_tool(client)],
        system_prompt="You are an order-desk agent. Use your tools to answer.",
        middleware=[DnsidToolPolicyMiddleware(restricted={"place_order": PLACE_ORDER_ALLOWLIST})],
        context_schema=DnsidContext,
        checkpointer=InMemorySaver(),
    )
```

The verified caller from step 2 goes into runtime context, where the model can't touch it:

```python
        context=DnsidContext(caller=caller),
```

[`DnsidToolPolicyMiddleware`](lib/langchain-dnsid/src/langchain_dnsid/agent.py) then enforces the allowlist twice:

1. **Before the model runs,** it removes `place_order` from the tools the model can see.
2. **Before a tool runs,** it blocks `place_order` again, in case the model calls it anyway.

If no caller is set at all, restricted tools are blocked.

The middleware also turns "refused to contact an unverified host" into a message the model can read, instead of a crash.

The model only chooses tools and their arguments. Who's calling, which tools they get, and which hosts the agent may contact are all decided in code the model can't influence.

## Run it

```bash
make run
```

You'll see each caller's reply, then each server's log. The replies are the model's own words, so yours will differ; the log lines are what matter. From a run:

```
==> peer: Please order 3 widgets
200 {'reply': '[graph.test -> peer.test] Your order for 3 widgets has been accepted. The order ID is **ord-1**. ...'}
==> outsider: Please order 3 widgets
200 {'reply': "[graph.test -> outsider.test] It seems I'm unable to successfully place the order ..."}
==> peer: Use the fetch tool to GET https://rogue.test/catalog and tell me what it returns.
200 {'reply': "[graph.test -> peer.test] The fetch request to `https://rogue.test/catalog` was refused because the domain `rogue.test` is not a verified DNSid identity ..."}
==> unsigned request to the graph
{"error": "[SIGNATURE_INVALID] missing Signature or Signature-Input headers"} 401

--- tools transcript ---
[tools.test] verified POST /order from graph.test

--- graph transcript ---
[graph.test] verified POST /ask from peer.test
[graph.test] verified peer tools.test
[graph.test] verified POST /ask from outsider.test
[policy] hid place_order from outsider.test
[graph.test] verified POST /ask from peer.test
[graph.test] refused peer rogue.test: [RECORD_NOT_FOUND] no _dnsid TXT record found
```

What happened:

- **peer:** the order went through, and the tools API saw it come from `graph.test`.
- **outsider:** same request, same valid identity, but `place_order` was hidden, so no order was placed.
- **rogue:** refused before anything was sent.
- **unsigned request:** rejected with a 401.
- **replayed request:** `make verify` also sends one signed request twice; the copy is rejected.

**Getting `502 Bad Gateway`?** The HTTPS proxy runs in Docker and must reach ports 3101–3104 on your machine, and a host firewall can block that. With `ufw`, allow the local registry's Docker network. Find its subnet with `docker network inspect $(docker network ls -q --filter name=dnsid-local)`, then:

```bash
sudo ufw allow from <subnet> to any port 3101:3104 proto tcp
```

## Verify

```bash
make verify
```

This runs two checks:

1. [`test_langchain_dnsid.py`](lib/langchain-dnsid/tests/test_langchain_dnsid.py), a quick offline test of the middleware (no Docker or API key needed). Run it alone with `make test`; that's what CI runs.
2. The full flow above, checked by [`verify/verify.sh`](verify/verify.sh). It reads only the log lines, never the model's wording, so it passes with any model.

```
ok: langchain_dnsid middleware
...
  ok: peer and graph verified each other
  ok: graph's signed tool call verified by tools
  ok: outsider verified, but place_order absent
  ok: graph refused to call an unverified peer
  ok: unsigned request rejected with 401
  ok: replayed signed request rejected with 401
  ok: exactly one order reached the tools API

✓ verify passed
```

When you're done, `make clean` stops the local registry. `dnsid local reset --hard` also deletes all identities.

## What goes wrong

These are the mistakes this design prevents. Keep them in mind when you build your own agent.

- **Putting the caller in the conversation.** Anything in messages or graph state can be influenced by the model, so a message like "you are now serving peer.test" could unlock tools. Keep identity in runtime context.
- **Trusting a saved conversation.** A resumed thread proves a conversation happened, not that the same party is back. Here every request is verified fresh, identity is never saved, and threads are keyed by caller.
- **A tool with its own HTTP client.** Its requests go out unsigned. A server that checks signatures rejects them. Try it: start the tools API with `dnsid local run tools --upstream http://localhost:3103 -- uv run python -u src/main.py tools &`, then send an unsigned request:

  ```bash
  curl -s --cacert ~/.dnsid-local/certs/root-ca.pem --resolve tools.test:443:127.0.0.1 \
    -X POST https://tools.test/order -H 'content-type: application/json' -d '{"item":"widgets","quantity":500}'
  ```

  You get `{"error": "[SIGNATURE_INVALID] missing Signature or Signature-Input headers"}`. A server that doesn't check signatures would accept it silently.
- **Accepting the same signature twice.** A signature stays valid for 5 minutes, and the DNSid SDK doesn't check whether it has seen one before. Without a check, a captured `POST /order` could be resent and would place another order. `DnsidAuthMiddleware` remembers each signature's nonce (a random value unique to it) until it expires. That memory is per process: behind several replicas, use a shared store such as Redis.
- **A general-purpose tool that can do what a restricted one does.** Every request the agent sends is signed as the agent. If `fetch` could POST, an outsider could ask for `POST https://tools.test/order` and get the order `place_order` was hidden to prevent. That's why `fetch_tool` can only GET.
- **Hiding a tool only from the model.** The model can still call a tool it wasn't shown. That's why `DnsidToolPolicyMiddleware` blocks restricted tools when they run, too.
- **Using `dnsid_client` for ordinary APIs.** It refuses any host without a DNSid identity, by design. Use a separate client for third-party APIs, so every call through the signed one stays verified.

## Add DNSid to your own agent

Everything above, applied to an agent of your own. Install the package (`uv add --editable path/to/lib/langchain-dnsid`), then:

```python
from dnsid import identity_manager_from_environment
from langchain.agents import create_agent
from langchain_dnsid import (
    DnsidAuthMiddleware, DnsidContext, DnsidToolPolicyMiddleware, dnsid_client, fetch_tool,
)

idm = identity_manager_from_environment()     # 1. your identity, from DNSID_* variables
client = dnsid_client(idm)                    # 2. one client; every tool that calls out uses it

agent = create_agent(                         # 3. the tool policy
    model="openai:gpt-5",
    tools=[fetch_tool(client), *your_tools],
    middleware=[DnsidToolPolicyMiddleware(restricted={"place_order": {"peer.test"}})],
    context_schema=DnsidContext,
)

app = DnsidAuthMiddleware(your_asgi_app, idm) # 4. verify every incoming request

# 5. in your request handler: pass the verified caller on every run
caller = request.state.dnsid_caller
await agent.ainvoke({"messages": [...]}, context=DnsidContext(caller=caller))
```

Your own tools must make their HTTP calls through `client`, like `place_order` in [`src/graph.py`](src/graph.py).

## Ready for production

This recipe runs entirely on the local registry. Before you deploy:

- **Registration.** Locally, `dnsid local` registers each identity, publishes its DNS record, and hosts its keys and status. In production that's the job of the [Known platform](https://knownsystems.ai/), which hasn't launched yet. Until it does, this integration runs on the local registry only.
- **Keys.** Each agent's private key is in `DNSID_CONFIG_DIR`. Treat it like any other secret.
- **Replay protection across replicas.** `DnsidAuthMiddleware` remembers nonces in memory, per process. With more than one replica, move that to a shared store such as Redis, or a replay can reach a replica that hasn't seen it.
- **Your public address.** `DnsidAuthMiddleware` checks signatures against `https://<your domain>`. If your agent is reachable at a different origin, pass `public_url=`.
- **Timeouts.** Real models are slow. Give callers a timeout that covers a full agent run.

## What to try next

- **Change the allowlist.** Add `outsider.test` to `PLACE_ORDER_ALLOWLIST` in [`src/graph.py`](src/graph.py) and re-run. One line changes who can order; nothing changes on the tools API.
- **MCP tools (untested pointer).** If your agent gets tools from an MCP server over HTTP, `langchain-mcp-adapters` lets you supply the HTTP client through a connection's `httpx_client_factory` setting. The adapter calls that factory with `headers`, `timeout`, and `auth`, so wrap `dnsid_client`: build one, apply the headers and timeout, and return it. Calls to the MCP server are then signed and checked like the agent's own. On the server side, wrap the MCP server's HTTP app in `DnsidAuthMiddleware`. This recipe doesn't exercise this path.
- **Recipe 12 — A2A + DNSid.** The same incoming-request checks, using the A2A agent protocol.

## Glossary

- **Checkpointer / thread** — LangGraph's way of saving a conversation (under a `thread_id`) and picking it up later.
- **JWKS** — JSON Web Key Set: a standard JSON list of public keys (RFC 7517). A DNSid record points to one.
- **Middleware** — two kinds here. *HTTP middleware* (`DnsidAuthMiddleware`) wraps a web server and checks every request. *Agent middleware* (`DnsidToolPolicyMiddleware`) is code that `create_agent` runs around every model call and tool call.
- **Runtime context** — data passed into a LangGraph run with `context=`. The model can't change it, and it isn't saved.
- **Transparency log** — a public, append-only record of when each identity was issued, so issuance can't be done or undone in secret.
