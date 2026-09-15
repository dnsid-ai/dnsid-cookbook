.PHONY: bootstrap run verify clean

DNSID_CLI ?= dnsid
ZONE ?= dev.dnsid.test
GRAPH_PORT ?= 3101
PEER_PORT ?= 3102
TOOLS_PORT ?= 3103
OUTSIDER_PORT ?= 3104

GRAPH_CU := https://graph.$(ZONE)/.well-known/agent-card.json

# Start the testnet and provision all four identities. Idempotent: `agent
# ensure` and `log issue` are safe to re-run for existing identities.
bootstrap:
	$(DNSID_CLI) testnet up
	$(DNSID_CLI) testnet agent ensure graph --upstream http://localhost:$(GRAPH_PORT) --cu "$(GRAPH_CU)" -- \
		$(DNSID_CLI) log issue --domain graph.$(ZONE)
	$(DNSID_CLI) testnet agent ensure tools --upstream http://localhost:$(TOOLS_PORT) -- \
		$(DNSID_CLI) log issue --domain tools.$(ZONE)
	$(DNSID_CLI) testnet agent ensure peer --upstream http://localhost:$(PEER_PORT) -- \
		$(DNSID_CLI) log issue --domain peer.$(ZONE)
	$(DNSID_CLI) testnet agent ensure outsider --upstream http://localhost:$(OUTSIDER_PORT) -- \
		$(DNSID_CLI) log issue --domain outsider.$(ZONE)
	uv sync

# Full flow: tools API and graph agent come up under `dnsid testnet run`, the
# allowlisted peer places an order through the graph's signed tool call, the
# outsider tries the same and finds the tool absent. Same script as
# `make verify`, without the transcript assertions.
run: bootstrap
	DNSID_RECIPE_ASSERT=0 bash verify/verify.sh

# One-shot check: runs the full flow and asserts the expected transcript
# (peer->graph ingress verified, graph->tools egress verified as the graph's
# domain, reply carries both identities, outsider sees the sensitive tool
# absent). Exits nonzero on any miss.
verify: bootstrap
	bash verify/verify.sh

clean:
	$(DNSID_CLI) testnet down
