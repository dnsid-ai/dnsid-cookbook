.PHONY: bootstrap run verify serve eval test clean
DNSID_CLI ?= dnsid
API_PORT ?= 3120
MODEL ?= decider-12b
MODEL_PORT ?= 8792
DECIDER_MODEL ?= Mapika/$(MODEL)

bootstrap:
	$(DNSID_CLI) local up --zone test
	$(DNSID_CLI) local agent ensure api --upstream http://localhost:$(API_PORT) -- \
	  $(DNSID_CLI) log issue --domain api.test
	$(DNSID_CLI) local agent ensure acme-billing --upstream http://localhost:3121 -- \
	  $(DNSID_CLI) log issue --domain acme-billing.test
	$(DNSID_CLI) local agent ensure paypal-refunds --upstream http://localhost:3122 -- \
	  $(DNSID_CLI) log issue --domain paypal-refunds.test
	uv sync --inexact

run: bootstrap
	DNSID_RECIPE_ASSERT=0 DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

verify: bootstrap
	DNSID_CLI=$(DNSID_CLI) API_PORT=$(API_PORT) bash verify/verify.sh

# Foreground server; downloads weights once. Ctrl-C stops only the model.
serve:
	DECIDER_MODEL=$(DECIDER_MODEL) uv run --group model uvicorn decider.serve:app \
	  --host 127.0.0.1 --port $(MODEL_PORT)

# MODEL is a request label; `serve` selects the actual Decider weights.
eval:
	JEV_MODEL=$(MODEL) JEV_ENDPOINT=$${JEV_ENDPOINT:-http://127.0.0.1:$(MODEL_PORT)/v1/systemone} \
	  uv run python src/eval.py cases $(EVAL_FLAGS)

test:
	uv run python -m unittest discover -s tests

clean:
	$(DNSID_CLI) local down
