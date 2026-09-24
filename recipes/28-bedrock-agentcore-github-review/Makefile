.PHONY: setup dev deploy invoke verify clean help

RUNTIME_ARN   ?=
CALLER_DOMAIN ?=
PR_OWNER      ?=
PR_REPO       ?=
PR_NUMBER     ?=

help:
	@echo "Targets: setup, dev, deploy, invoke, verify, clean"

setup:
	@test -f agentcore/.env.local || cp agentcore/.env.local.example agentcore/.env.local
	cd app/GitHubReviewBot && uv sync
	@echo "→ Fill in agentcore/.env.local, then run: make dev"

dev:
	agentcore dev --logs

deploy:
	agentcore deploy

verify: setup
	cd app/GitHubReviewBot && uv run python -m unittest test_dnsid_identity.py test_review_scope.py

invoke:
	@test -n "$(RUNTIME_ARN)"   || (echo "RUNTIME_ARN is required"   && exit 1)
	@test -n "$(CALLER_DOMAIN)" || (echo "CALLER_DOMAIN is required" && exit 1)
	@test -n "$(PR_OWNER)"      || (echo "PR_OWNER is required"      && exit 1)
	@test -n "$(PR_REPO)"       || (echo "PR_REPO is required"       && exit 1)
	@test -n "$(PR_NUMBER)"     || (echo "PR_NUMBER is required"     && exit 1)
	./scripts/invoke.sh \
		--runtime-arn "$(RUNTIME_ARN)" \
		--token "$$(dnsid token --domain $(CALLER_DOMAIN))" \
		--prompt "Review PR #$(PR_NUMBER) in $(PR_OWNER)/$(PR_REPO)"

clean:
	cd agentcore/cdk && npm ci && npm run cdk -- destroy --all --force
