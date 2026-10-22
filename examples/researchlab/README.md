# researchlab

An example of DNSid for a multi-agent setup: a lab of AI agents, each with
its own verifiable identity, pulls data from a service that checks who is
asking. When the lab revokes one of its agents, the service refuses that
agent on its next request.

Built with the Claude Agent SDK and the DNSid plugin
(`@dnsid-ai/agent-sdk-plugin`), on DNSid Local.

## The pieces

| Who | Identity | Code | What it does |
|---|---|---|---|
| Coordinator | `researchlab.test` | `src/coordinator.ts` | Splits the research task and dispatches researchers. It is the accountable entity for every researcher. |
| Researchers | `researcher-N.researchlab.test` | `src/researcher.ts` | One Agent SDK session each. The plugin brings the identity online at startup and signs every request. Their only tool is the plugin's signing `fetch`. |
| Data service | `publicdata.test` | `src/publicdata/server.ts` | Verifies every request (signature, identity, live status), then logs the agent, its accountable entity, and its status to `logs/publicdata.jsonl`. |
| Revocation | | `src/revoke.ts` | The lab revokes a researcher through the registry. |

## Run it

You need Node 24.22.1+ on the 24.x line, or Node 26.12.1+, the `dnsid` CLI,
DNSid Local (`dnsid local up --zone test`), and a Claude login or
`ANTHROPIC_API_KEY`.

The Node.js minimum includes the emSign compromised-intermediate block. The
DNSid SDKs stay at `0.24.2`: plugin `0.0.1` cannot bring a new identity online
with SDK `0.31.0`. Upgrade them together when the plugin supports the new
startup verification.

```bash
npm install
scripts/demo.sh
```

The demo does the following:

1. Starts publicdata.test.
2. Runs the lab on the default task: compare health spending across five
   countries. The report goes to `reports/latest.md`.
3. Revokes the last researcher the lab used.
4. Has that researcher send its next request. You get HTTP 401, and the
   log shows `StatusNotActive ... REVOKED`.

To use your own task, run `scripts/demo.sh "Compare France, Canada, and India."`.

You can also run each step on its own:

```bash
npm run publicdata                          # in its own terminal
npm run lab -- "<task>"
npm run revoke -- <n>                       # permanent
npm run researcher -- <n> DEU,GBR "<brief>"
```

## Settings

| Variable | Default | |
|---|---|---|
| `LAB_MODEL` | `claude-opus-5-5` | Coordinator model |
| `RESEARCHER_MODEL` | `claude-sonnet-5-5` | Researcher model |
| `PUBLICDATA_PORT` | `3103` | The port DNSid Local's proxy forwards publicdata.test to |
| `PUBLICDATA_TRUSTED_ENTITIES` | unset | Comma-separated allowlist of accountable entities. If unset, any ACTIVE agent can read. |
| `LAB_DEBUG` | unset | Set to `1` to show Claude Code's stderr |

## Try it with your coding agent

`AGENTS.md` gives a coding agent the context to run, explain, and change
this example. Install the [DNSid agent skills](https://github.com/dnsid-ai/skills)
first, then start your agent in this directory.

- Claude Code: `/plugin marketplace add dnsid-ai/skills`, then
  `/plugin install dnsid-skills@dnsid`
- Other agents: `npx skills add dnsid-ai/skills`

## Good to know

- **Revocation is permanent.** Each demo run uses up one researcher number.
  The lab skips revoked numbers.
- **A revoked researcher won't send on its own.** The plugin tells it that
  it is revoked, so the demo tells it to send anyway. The control that
  matters is the server's refusal.
- **`dnsid revoke` isn't used.** On this DNSid Local build, that command
  can't find the agent, so `src/dnsid-local.ts` calls the registry's revoke
  API through the SDK.
- **The data is illustrative.** The figures are rounded approximations of
  WHO and OECD 2021 data. Don't cite them.
