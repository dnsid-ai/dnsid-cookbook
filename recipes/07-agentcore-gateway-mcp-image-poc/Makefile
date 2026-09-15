.PHONY: setup probe-model probe-gateway deploy-gateway verify verify-gateway test coverage dev verify-local clean-artifacts clean-gateway

PYTHON ?= python3
VENV := .venv
VENV_PY := $(VENV)/bin/python
HOST ?= 127.0.0.1
PORT ?= 8787
AWS_REGION ?= us-west-2
BEDROCK_IMAGE_MODEL_ID ?= stability.sd3-5-large-v1:0
DNSID_CLI ?= dnsid
DNSID_SERVER ?= https://api.dnsid.dev
DNSID_AGENT_DOMAIN ?=
IMAGE_POC_MODE ?= gateway
GATEWAY_STATE_PATH ?= .artifacts/gateway/phase3-state.json
DNSID_ENV := DNSID_CLI="$(DNSID_CLI)" DNSID_SERVER="$(DNSID_SERVER)" DNSID_AGENT_DOMAIN="$(DNSID_AGENT_DOMAIN)"
UI_ENV := $(DNSID_ENV) IMAGE_POC_MODE="$(IMAGE_POC_MODE)" GATEWAY_STATE_PATH="$(GATEWAY_STATE_PATH)"

setup: $(VENV)/.installed

$(VENV)/.installed: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -e ".[dev]"
	touch $(VENV)/.installed

probe-model: setup
	AWS_REGION="$(AWS_REGION)" $(VENV_PY) scripts/probe_bedrock_model.py

probe-gateway: setup
	$(DNSID_ENV) $(VENV_PY) scripts/probe_gateway_surfaces.py

deploy-gateway: setup
	$(DNSID_ENV) $(VENV_PY) scripts/deploy_gateway_phase3.py

verify: verify-gateway

verify-gateway: setup
	$(DNSID_ENV) $(VENV_PY) scripts/verify_gateway.py

test: setup
	$(VENV_PY) -m pytest

coverage: setup
	$(VENV_PY) -m coverage run -m pytest
	$(VENV_PY) -m coverage report --show-missing

dev: setup
	$(UI_ENV) HOST="$(HOST)" PORT="$(PORT)" AWS_REGION="$(AWS_REGION)" BEDROCK_IMAGE_MODEL_ID="$(BEDROCK_IMAGE_MODEL_ID)" $(VENV_PY) -m image_poc.server

verify-local: setup
	$(UI_ENV) HOST="$(HOST)" PORT="$(PORT)" $(VENV_PY) scripts/verify_local.py

clean-artifacts:
	rm -rf .artifacts

clean-gateway:
	@echo "Phase 3 AWS cleanup is intentionally manual; inspect .artifacts/gateway/phase3-state.json first."
