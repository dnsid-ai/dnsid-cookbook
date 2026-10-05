.PHONY: bootstrap run verify serve eval pi clean
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

# Foreground local decision server. Downloads/caches weights once; Ctrl-C stops it.
serve:
	llama serve -hf ggml-org/Clef-Flash-GGUF:Q4_K_M --alias clef-flash \
	  --no-mmproj --host 127.0.0.1 --port 8080 -c 4096

# Optional live naming check; start make serve first. No chat-model account needed.
eval: bootstrap
	npm run check
	$(DNSID_CLI) local run shopper -- npm run demo -- --local-model

# Optional interactive run: start `npm run merchant` in another terminal first.
pi: bootstrap
	$(DNSID_CLI) local run shopper -- \
	  npx --no-install pi --no-extensions -e src/extension.ts -e builtin:codemode \
	  --tools codemode,dnsid_inspect,dnsid_catalog,dnsid_pay $(PI_ARGS)

clean:
	$(DNSID_CLI) local down
