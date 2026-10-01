.PHONY: bootstrap run verify pi clean
DNSID_CLI ?= dnsid
MERCHANT_PORT ?= 3133

bootstrap:
	$(DNSID_CLI) local up --zone test
	$(DNSID_CLI) local agent ensure shopper --upstream http://localhost:$(MERCHANT_PORT) -- \
	  $(DNSID_CLI) log issue --domain shopper.test
	$(DNSID_CLI) local agent ensure merchant --upstream http://localhost:$(MERCHANT_PORT) -- \
	  $(DNSID_CLI) log issue --domain merchant.test
	$(DNSID_CLI) local agent ensure paypal-payments --upstream http://localhost:$(MERCHANT_PORT) -- \
	  $(DNSID_CLI) log issue --domain paypal-payments.test
	npm ci --ignore-scripts

run: verify

verify: bootstrap
	npm run check
	MERCHANT_PORT=$(MERCHANT_PORT) DNSID_CLI=$(DNSID_CLI) bash verify.sh

# Optional interactive run: start `npm run merchant` in another terminal first.
pi: bootstrap
	$(DNSID_CLI) local run shopper -- \
	  npx --no-install pi --no-extensions -e src/extension.ts -e builtin:codemode \
	  --tools codemode,dnsid_inspect,dnsid_catalog,dnsid_pay $(PI_ARGS)

clean:
	$(DNSID_CLI) local down
