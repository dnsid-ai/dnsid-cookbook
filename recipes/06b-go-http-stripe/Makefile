.PHONY: bootstrap build run verify clean

DNSID_CLI ?= dnsid
GO ?= go
ZONE ?= dev.dnsid.test
STRIPE_PORT ?= 3301
WRITER_PORT ?= 3302
ACCOUNT ?= acct_demo
AMOUNT ?= 250

STRIPE_DOMAIN := stripe.$(ZONE)
WRITER_DOMAIN := writer.$(ZONE)
GOPRIVATE ?= github.com/Identity-Digital/*
export GOPRIVATE

bootstrap: build
	$(DNSID_CLI) testnet up
	$(DNSID_CLI) testnet agent ensure stripe --upstream http://localhost:$(STRIPE_PORT) -- \
		$(DNSID_CLI) log issue --domain $(STRIPE_DOMAIN)
	$(DNSID_CLI) testnet agent ensure writer --upstream http://localhost:$(WRITER_PORT) -- \
		$(DNSID_CLI) log issue --domain $(WRITER_DOMAIN)

build:
	$(GO) mod download
	$(GO) build -o bin/server ./src/server
	$(GO) build -o bin/agent ./src/agent

run: bootstrap
	DNSID_RECIPE_ASSERT=0 bash verify/verify.sh

verify: bootstrap
	bash verify/verify.sh

clean:
	$(DNSID_CLI) testnet down
	rm -rf bin
