.PHONY: bootstrap model run test verify clean

DNSID_CLI ?= dnsid
ZONE ?= test
GRAPH_PORT ?= 3101
PEER_PORT ?= 3102
TOOLS_PORT ?= 3103
OUTSIDER_PORT ?= 3104

# Start the local registry and provision all four identities. Idempotent: `agent
# ensure` and `log issue` are safe to re-run for existing identities. The local
# registry publishes each identity's _dnsid record and hosts its JWKS and status.
bootstrap:
	$(DNSID_CLI) local up --zone $(ZONE)
	$(DNSID_CLI) local agent ensure graph --upstream http://localhost:$(GRAPH_PORT) -- \
		$(DNSID_CLI) log issue --domain graph.$(ZONE)
	$(DNSID_CLI) local agent ensure tools --upstream http://localhost:$(TOOLS_PORT) -- \
		$(DNSID_CLI) log issue --domain tools.$(ZONE)
	$(DNSID_CLI) local agent ensure peer --upstream http://localhost:$(PEER_PORT) -- \
		$(DNSID_CLI) log issue --domain peer.$(ZONE)
	$(DNSID_CLI) local agent ensure outsider --upstream http://localhost:$(OUTSIDER_PORT) -- \
		$(DNSID_CLI) log issue --domain outsider.$(ZONE)
	# --inexact keeps a model provider package you added with `uv pip install`.
	uv sync --inexact

# The agent needs a real model: any LangChain "provider:model" string, with that
# provider's package installed and its API key set (README, step 1).
model:
	@test -n "$$DNSID_RECIPE_MODEL" || { echo 'Set DNSID_RECIPE_MODEL, e.g. DNSID_RECIPE_MODEL=anthropic:claude-sonnet-5 (README, step 1)'; exit 1; }

# Full flow, same script as `make verify`, without the transcript assertions.
run: model bootstrap
	DNSID_RECIPE_ASSERT=0 bash verify/verify.sh

# Offline module check: fake model, real signatures. No registry, no API key.
# This is what CI runs.
test:
	uv run python lib/langchain-dnsid/tests/test_langchain_dnsid.py

# Offline check, then the full flow with transcript assertions.
verify: model bootstrap test
	bash verify/verify.sh

clean:
	$(DNSID_CLI) local down
