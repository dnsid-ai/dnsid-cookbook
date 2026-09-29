.PHONY: bootstrap run verify eval test clean
DNSID_CLI ?= dnsid
API_PORT ?= 3120

bootstrap:
	$(DNSID_CLI) local up
	$(DNSID_CLI) local agent ensure api --upstream http://localhost:$(API_PORT) -- \
	  $(DNSID_CLI) log issue --domain api.dev.dnsid.test
	$(DNSID_CLI) local agent ensure acme-billing --upstream http://localhost:3121 -- \
	  $(DNSID_CLI) log issue --domain acme-billing.dev.dnsid.test
	$(DNSID_CLI) local agent ensure paypal-refunds --upstream http://localhost:3122 -- \
	  $(DNSID_CLI) log issue --domain paypal-refunds.dev.dnsid.test
	uv sync

run: bootstrap
	DNSID_RECIPE_ASSERT=0 DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

verify: bootstrap
	DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

# Needs a real decision server: JEV_ENDPOINT=... make eval
eval:
	uv run python src/eval.py cases

test:
	uv run python -m unittest discover -s tests

clean:
	$(DNSID_CLI) local down
