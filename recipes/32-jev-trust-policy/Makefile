.PHONY: bootstrap run verify serve eval test clean
DNSID_CLI ?= dnsid
API_PORT ?= 3120
MODEL ?= clef-flash
MODEL_PORT ?= 8080
LLAMA_SERVE ?= llama serve

bootstrap:
	$(DNSID_CLI) local up --zone test
	$(DNSID_CLI) local agent ensure api --upstream http://localhost:$(API_PORT) -- \
	  $(DNSID_CLI) log issue --domain api.test
	$(DNSID_CLI) local agent ensure acme-billing --upstream http://localhost:3121 -- \
	  $(DNSID_CLI) log issue --domain acme-billing.test
	$(DNSID_CLI) local agent ensure paypal-refunds --upstream http://localhost:3122 -- \
	  $(DNSID_CLI) log issue --domain paypal-refunds.test
	uv sync

run: bootstrap
	DNSID_RECIPE_ASSERT=0 DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

verify: bootstrap
	DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

# Foreground local decision server; downloads/caches weights once. Ctrl-C stops it.
serve:
	@$(LLAMA_SERVE) --version 2>&1 | grep -q '1537a0a8b' || \
	  { echo 'Use llama.cpp build 11379 (1537a0a8b); see README. Set LLAMA_SERVE to its server command.' >&2; exit 1; }
	$(LLAMA_SERVE) -hf ggml-org/Clef-Flash-GGUF:Q4_K_M --alias $(MODEL) \
	  --no-mmproj --host 127.0.0.1 --port $(MODEL_PORT) -c 4096

# MODEL is a request label; it cannot switch a running server's weights.
eval:
	JEV_MODEL=$(MODEL) JEV_ENDPOINT=$${JEV_ENDPOINT:-http://127.0.0.1:$(MODEL_PORT)/v1/systemone} \
	  uv run python src/eval.py cases $(EVAL_FLAGS)

test:
	uv run python -m unittest discover -s tests

clean:
	$(DNSID_CLI) local down
