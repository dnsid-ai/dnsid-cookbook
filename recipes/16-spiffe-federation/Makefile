.PHONY: guard bootstrap run verify test stop clean checkpoints-status checkpoints-reset

DNSID_CLI ?= dnsid
ZONE ?= test
REGISTRY_PORT ?= 7965
DNS_PORT ?= 7963
# Must be 443: the local registry writes a non-default proxy port into every published URL and into the
# transparency log origin, and the containers reach the proxy on 443 inside its Docker network.
PROXY_PORT ?= 443

# Run from the recipe directory itself (make -C ...), reached by its real path: every path below is anchored
# there, and the dnsid CLI derives its instance labels from the literal state path.
RECIPE_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
ifneq ($(CURDIR),$(RECIPE_DIR))
$(error run this Makefile from its own directory by its real path: make -C $(RECIPE_DIR))
endif

# This recipe's own local registry state, isolated from ~/.dnsid-local and from every other demo. It is not
# configurable: any other STATE (command line or environment) is refused before a single command runs.
RECIPE_LOCAL_STATE := $(CURDIR)/.dnsid-local
STATE ?= $(RECIPE_LOCAL_STATE)
ifneq ($(STATE),$(RECIPE_LOCAL_STATE))
$(error refusing STATE=$(STATE): this recipe only operates on its own $(RECIPE_LOCAL_STATE))
endif

export DNSID_LOCAL_STATE := $(STATE)
export DNSID_LOCAL_REGISTRY_PORT := $(REGISTRY_PORT)
export DNSID_LOCAL_DNS_PORT := $(DNS_PORT)
export DNSID_LOCAL_PROXY_PORT := $(PROXY_PORT)
COMPOSE := docker compose -p dnsid-recipe16 --project-directory $(CURDIR) -f $(CURDIR)/compose.yaml
COMPOSE_ENV = $(if $(wildcard $(CURDIR)/.state/compose.env),--env-file $(CURDIR)/.state/compose.env)

# Runtime check (canonical path, recipe directory not reached through a symlink, state not a symlink).
guard:
	@python3 -I scripts/paths.py check-state "$(STATE)"

$(STATE)/config.yml: | guard
	@mkdir -p $(STATE)
	@printf '%s\n' \
		'zone: $(ZONE)' \
		'defaults:' \
		'  registryUrl: http://localhost:$(REGISTRY_PORT)' \
		'  proxyPort: "$(PROXY_PORT)"' \
		'agents: {}' > $@

# Local registry up (dnsid CLI), two SPIRE trust domains, workloads, and Acme's federation controller.
# Idempotent: safe to re-run, and resumes preserved state after `make stop`. A restart reuses the existing
# federation signer (only once the registry confirms it ACTIVE), its entity-key pin and the checkpoint store;
# it never reissues, replaces or re-pins them, and stops with a named reason instead.
bootstrap: guard $(STATE)/config.yml
	bash scripts/bootstrap.sh

# The three acts, human-watchable: same flow as `make verify`, checks reported but not fatal.
run: bootstrap
	DNSID_RECIPE_ASSERT=0 bash verify/verify.sh

# Offline unit tests (no Docker, no network, no local registry).
test:
	uv run --frozen pytest -q

# One-shot: offline tests, then the three acts with every expected result asserted. Exits nonzero on any
# miss. Act 3 permanently revokes the federation signer, and a revoked signer is never reused or replaced
# automatically: a second `make verify` in the same environment stops at bootstrap (SIGNER UNUSABLE). To
# repeat the full lifecycle, use a new isolated environment (a fresh clone); there is no rotation command yet.
verify: test bootstrap
	DNSID_RECIPE_ASSERT=1 bash verify/verify.sh

# Non-destructive: stop this recipe's containers and its local registry, keeping every volume, the local
# registry state, the checkpoint history and journal, the audit log, pins, policy and identities. The
# publisher stops first (nothing new can be approved); the controller next, while SPIRE is still up, so its
# orderly shutdown can withdraw the trust it installed. `make bootstrap` resumes from the preserved state.
stop: guard
	$(COMPOSE) $(COMPOSE_ENV) stop rackloria-publisher
	$(COMPOSE) $(COMPOSE_ENV) stop acme-dnsid-controller
	$(COMPOSE) $(COMPOSE_ENV) stop
	$(DNSID_CLI) local down --state $(STATE)

# Operator actions for the controller's trusted C2SP checkpoint store (run inside the controller image).
checkpoints-status: guard
	$(COMPOSE) $(COMPOSE_ENV) run --rm --no-deps acme-dnsid-controller \
		dnsidfed.checkpoints status --state-dir /var/lib/dnsidfed

# Accept a NEW trust baseline after investigating a CHECKPOINT_STORE_FAILED. Stops the controller first;
# archives the old store and journals REASON. Restart with `make bootstrap`.
checkpoints-reset: export REASON := $(REASON)
checkpoints-reset: guard
	@test -n "$$REASON" || { echo 'usage: make checkpoints-reset REASON="why a new baseline is acceptable"'; exit 2; }
	$(COMPOSE) $(COMPOSE_ENV) stop acme-dnsid-controller
	$(COMPOSE) $(COMPOSE_ENV) run --rm --no-deps acme-dnsid-controller \
		dnsidfed.checkpoints reset --state-dir /var/lib/dnsidfed --confirm-new-baseline --reason "$$REASON"

# Destructive and deliberate: lists exactly what it removes; refuses to delete checkpoint history without
# CONFIRM=delete-checkpoint-history; archives that history to .archive/ first. See scripts/cleanup.py.
clean: export CONFIRM := $(CONFIRM)
clean: guard
	python3 -I scripts/cleanup.py --state "$(STATE)"
