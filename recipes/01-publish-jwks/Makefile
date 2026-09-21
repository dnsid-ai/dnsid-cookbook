.PHONY: bootstrap run verify clean

DNSID_CLI ?= dnsid
ZONE ?= dev.dnsid.test
DOMAIN := publish.$(ZONE)
PORT ?= 3201

# Start the local registry and provision the identity: keypair, registration,
# challenge, published `_dnsid` record, countersigned log entry. Idempotent.
bootstrap:
	$(DNSID_CLI) local up
	$(DNSID_CLI) local agent ensure publish --upstream http://localhost:$(PORT) -- \
		$(DNSID_CLI) log issue --domain $(DOMAIN)

# Serve the JWKS in the foreground (Ctrl-C to stop) so you can inspect the
# published identity from another terminal with dig and curl.
run: bootstrap
	$(DNSID_CLI) local run publish --upstream http://localhost:$(PORT) -- \
		python3 -u src/serve.py

# One-shot: start the JWKS server, then check the published identity the way
# a verifier would — resolve the TXT binding, follow ku= to the keys, match
# the kid against the local keypair, follow su= to live status.
verify: bootstrap
	$(DNSID_CLI) local run publish --upstream http://localhost:$(PORT) -- \
		bash verify/verify.sh

clean:
	$(DNSID_CLI) local down
