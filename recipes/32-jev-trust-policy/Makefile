.PHONY: bootstrap run verify clean
DNSID_CLI ?= dnsid
API_PORT ?= 3120

bootstrap:
	$(DNSID_CLI) local up
	$(DNSID_CLI) local agent ensure api --upstream http://localhost:$(API_PORT) -- \
		$(DNSID_CLI) log issue --domain api.dev.dnsid.test
	$(DNSID_CLI) local agent ensure peer --upstream http://localhost:3121 -- \
		$(DNSID_CLI) log issue --domain peer.dev.dnsid.test
	$(DNSID_CLI) local agent ensure outsider --upstream http://localhost:3122 -- \
		$(DNSID_CLI) log issue --domain outsider.dev.dnsid.test
	uv sync

run: bootstrap
	DNSID_RECIPE_ASSERT=0 DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

verify: bootstrap
	DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

clean:
	$(DNSID_CLI) local down
