.PHONY: setup probe-oidc probe-model deploy-gateway verify verify-gateway teardown-gateway test coverage clean-artifacts

PYTHON ?= python3
VENV := .venv
VENV_PY := $(VENV)/bin/python

AGENTCORE_REGION ?= us-east-1
BEDROCK_REGION ?= us-west-2
BEDROCK_IMAGE_MODEL_ID ?= stability.sd3-5-large-v1:0
DNSID_SERVER ?= https://oidc.dev.dnsid.ai
DNSID_AGENT_DOMAIN ?=
DNSID_ENV := DNSID_SERVER="$(DNSID_SERVER)" DNSID_AGENT_DOMAIN="$(DNSID_AGENT_DOMAIN)"
AWS_ENV := AGENTCORE_REGION="$(AGENTCORE_REGION)" BEDROCK_REGION="$(BEDROCK_REGION)" BEDROCK_IMAGE_MODEL_ID="$(BEDROCK_IMAGE_MODEL_ID)"

setup: $(VENV)/.installed

$(VENV)/.installed: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -e ".[dev]"
	touch $(VENV)/.installed

probe-oidc: setup
	$(DNSID_ENV) $(VENV_PY) scripts/probe_oidc.py

probe-model: setup
	$(AWS_ENV) $(VENV_PY) scripts/probe_bedrock_model.py

deploy-gateway: setup
	$(DNSID_ENV) $(AWS_ENV) $(VENV_PY) scripts/deploy_gateway.py

verify: verify-gateway

verify-gateway: setup
	$(DNSID_ENV) $(AWS_ENV) $(VENV_PY) scripts/verify_gateway.py

teardown-gateway: setup
	$(AWS_ENV) $(VENV_PY) scripts/teardown_gateway.py

test: setup
	$(VENV_PY) -m pytest

coverage: setup
	$(VENV_PY) -m coverage run -m pytest
	$(VENV_PY) -m coverage report --show-missing

clean-artifacts:
	rm -rf .artifacts
