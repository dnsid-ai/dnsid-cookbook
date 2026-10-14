# AGENTS.md

This project is a runnable example of DNSid for a multi-agent setup. Read
`README.md` first, because it describes what the project shows. This file
gives you what you need to run, change, and explain it.

## Skills

Use the DNSid agent skills from
[dnsid-ai/skills](https://github.com/dnsid-ai/skills) for DNSid questions
instead of guessing. If they aren't installed, ask the user to install them:

- Claude Code: `/plugin marketplace add dnsid-ai/skills`, then
  `/plugin install dnsid-skills@dnsid`
- Other agents: `npx skills add dnsid-ai/skills`

The skills are:

- `dnsid`: the protocol (the `_dnsid` record, keys, lifecycle, what
  verification proves)
- `dnsid-cli`: the `dnsid` CLI and DNSid Local
- `dnsid-sdk`: SDK code (verification, HTTP signatures, the registry client)
- `dnsid-integrations`: the Claude Agent SDK plugin that this project uses

## Running it

```bash
npm install
dnsid local up --zone test   # safe if it is already up; it keeps existing state
npm run typecheck       # the only static check; there are no tests
scripts/demo.sh         # the full story, about 1-2 minutes
```

The demo calls the Claude API, which costs money, and it **permanently
revokes one researcher identity**. To check a change without the full demo,
start `npm run publicdata` in the background and then run one researcher:
`npm run researcher -- 1 DEU`. When you finish, stop the server.

To see the result of a run, look at these files:

- `logs/publicdata.jsonl`: one line per request, with the decision `served`
  or `refused`
- `reports/latest.md`: the coordinator's report
- `reports/researchers.json`: what each researcher requested and got back

## Layout

- `src/coordinator.ts`: the `researchlab.test` session. It has one MCP tool,
  `dispatch_researchers`.
- `src/researcher.ts`: the `researcher-N.researchlab.test` sessions. The
  model has only the plugin's `fetch` and `verify` tools, and
  `tools: []` turns off the built-in tools.
- `src/publicdata/server.ts`: the verifying HTTP server. It requires the
  signature tag `publicdata-v1` and rejects replays.
- `src/publicdata/dataset.ts`: the illustrative data.
- `src/dnsid-local.ts`: the `dnsid` CLI calls (ensure, status, issue) and an
  SDK revoke.
- `src/revoke.ts`: the lab revokes a researcher.
- `scripts/demo.sh`: runs the whole flow from start to end.

Node 24 runs the TypeScript directly, so there is no build step. Imports use
`.ts` extensions.

## Rules

- **DNSid Local is shared with other projects.** Never run
  `dnsid local reset` or `dnsid local down`. Never revoke or remove agents
  that are not under `researchlab.test` or `publicdata.test`.
- **Revocation can't be undone.** Revoke only when the user asks you to, or
  as part of `scripts/demo.sh`.
- **Ports:** DNSid Local's HTTPS proxy runs in Docker and forwards
  `https://<name>.test` to a host port. publicdata.test listens on port 3103
  on all interfaces. If a host firewall blocks the proxy, change
  `PUBLICDATA_PORT` to a port the firewall allows.
- **Keep the `@dnsid-ai/*` versions pinned** to the plugin's minor version.
  If npm installs a second copy of `@dnsid-ai/protocol`, the
  `instanceof VerificationError` check in the server stops working.
- **Every agent gets its own environment.** Each session gets its own
  `DNSID_*` variables and its own verdict cache in `.dnsid-verdicts/`.
  Never let a researcher inherit the coordinator's `DNSID_*` variables.
- In a refusal log line, `claimed_accountable` and `claimed_state` come from
  a lookup that is done only for logging. They are not verified, so never use
  them to make a decision.
