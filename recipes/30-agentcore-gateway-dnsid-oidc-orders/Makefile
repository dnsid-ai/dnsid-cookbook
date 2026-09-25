.PHONY: bootstrap deploy run verify clean test

UV ?= uv
export AWS_REGION ?= us-east-1
export AGENTCORE_REGION ?= us-east-1
export DNSID_SERVER ?= https://api.dev.dnsid.ai

bootstrap:
	$(UV) sync --extra dev
	$(UV) run python -u -m scripts.bootstrap

deploy: bootstrap
	$(UV) run python -u -m scripts.deploy

run:
	$(UV) run python -u -m scripts.run

verify:
	$(UV) run python -u -m scripts.verify

clean:
	$(UV) sync --extra dev
	$(UV) run python -u -m scripts.clean

test:
	$(UV) sync --extra dev
	$(UV) run pytest
