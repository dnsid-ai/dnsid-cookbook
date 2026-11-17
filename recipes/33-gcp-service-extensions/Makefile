# The local mode (DNSid Local): the cookbook's four targets. Needs Docker, the dnsid CLI and Node.js 24.22.3 or later;
# no cloud account. See README.md, "Run it locally (DNSid Local)". The cloud deployment is scripts/deploy.sh.
.PHONY: bootstrap run verify clean

NODE ?= node

# DNSid Local up in this mode's own state directory, alice.test issued, bob.test issued then revoked. Safe to re-run.
bootstrap: node_modules/.package-lock.json
	$(NODE) local/recipe.ts bootstrap

# The local request path (edge -> verifier -> Demo Bank) started in the background; a running one is reused.
run: bootstrap
	$(NODE) local/recipe.ts run

# Signed and unsigned requests through that path, every outcome checked. Exits nonzero on any miss.
verify: run
	$(NODE) local/recipe.ts verify

# Stops the request path and removes this mode's DNSid Local and state. Safe after a partial start, and to re-run.
clean: node_modules/.package-lock.json
	$(NODE) local/recipe.ts clean

node_modules/.package-lock.json: package.json package-lock.json
	npm ci --no-audit --no-fund
