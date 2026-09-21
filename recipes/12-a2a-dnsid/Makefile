.PHONY: bootstrap run verify clean

DNSID_CLI ?= dnsid
ZONE ?= dev.dnsid.test
ALICE_PORT ?= 3001
BOB_PORT ?= 3002

ALICE_CU := https://alice.$(ZONE)/.well-known/agent-card.json
BOB_CU := https://bob.$(ZONE)/.well-known/agent-card.json

# Start the local registry and provision both identities. Idempotent: `agent ensure`
# and `log issue` are safe to re-run for existing identities.
bootstrap:
	$(DNSID_CLI) local up
	$(DNSID_CLI) local agent ensure bob --upstream http://localhost:$(BOB_PORT) --cu "$(BOB_CU)" -- \
		$(DNSID_CLI) log issue --domain bob.$(ZONE)
	$(DNSID_CLI) local agent ensure alice --upstream http://localhost:$(ALICE_PORT) --cu "$(ALICE_CU)" -- \
		$(DNSID_CLI) log issue --domain alice.$(ZONE)
	uv sync

# Full flow: Bob comes up under `dnsid local run`, Alice sends one signed
# message, both identities verified. Same script as `make verify`, without
# the transcript assertions.
run: bootstrap
	DNSID_RECIPE_ASSERT=0 bash verify/verify.sh

# One-shot check: runs the full flow and asserts the expected transcript
# (identity published, signature verified on Bob, reply carries both verified
# identities). Exits nonzero on any miss.
verify: bootstrap
	bash verify/verify.sh

clean:
	$(DNSID_CLI) local down
