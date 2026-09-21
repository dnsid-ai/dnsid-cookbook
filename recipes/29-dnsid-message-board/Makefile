.PHONY: bootstrap build test run verify clean

DNSID_CLI ?= dnsid
GO ?= go
ZONE ?= dev.dnsid.test
STATE ?= $(CURDIR)/.dnsid-local
REGISTRY_PORT ?= 7955
DNS_PORT ?= 7753
PROXY_PORT ?= 443
BOARD_PORT ?= 3401
OWNER_PORT ?= 3402
POSTER_PORT ?= 3403
AUDIENCE ?= urn:dnsid-message-board:testnet
TOKEN_ENVIRONMENT ?= production

BOARD_DOMAIN := board.$(ZONE)
OWNER_DOMAIN := owner.$(ZONE)
POSTER_DOMAIN := poster.$(ZONE)
LOCAL := env DNSID_LOCAL_REGISTRY_PORT=$(REGISTRY_PORT) DNSID_LOCAL_DNS_PORT=$(DNS_PORT) DNSID_LOCAL_PROXY_PORT=$(PROXY_PORT) $(DNSID_CLI) local
GOPRIVATE ?= github.com/Identity-Digital/*
export GOPRIVATE

$(STATE)/config.yml:
	@mkdir -p $(STATE)
	@printf '%s\n' \
		'zone: $(ZONE)' \
		'defaults:' \
		'  registryUrl: http://localhost:$(REGISTRY_PORT)' \
		'  proxyPort: "$(PROXY_PORT)"' \
		'agents: {}' > $@

bootstrap: build $(STATE)/config.yml
	$(LOCAL) up --state $(STATE)
	$(LOCAL) agent ensure board --state $(STATE) --upstream http://localhost:$(BOARD_PORT) -- \
		$(DNSID_CLI) log issue --domain $(BOARD_DOMAIN)
	$(LOCAL) agent ensure owner --state $(STATE) --upstream http://localhost:$(OWNER_PORT) -- \
		$(DNSID_CLI) log issue --domain $(OWNER_DOMAIN)
	$(LOCAL) agent ensure poster --state $(STATE) --upstream http://localhost:$(POSTER_PORT) -- \
		$(DNSID_CLI) log issue --domain $(POSTER_DOMAIN)

build:
	$(GO) mod download
	mkdir -p bin
	$(GO) build -o bin/dnsid-board ./src/cmd/dnsid-board
	$(GO) build -o bin/dnsid-board-server ./src/cmd/dnsid-board-server

test:
	$(GO) test ./...

run: bootstrap
	$(LOCAL) run board --state $(STATE) --upstream http://localhost:$(BOARD_PORT) -- \
		env BOARD_BACKEND=local ADDR=:$(BOARD_PORT) BOARD_API_AUDIENCES=$(AUDIENCE) DNSID_ENVIRONMENT=$(TOKEN_ENVIRONMENT) \
		$(CURDIR)/bin/dnsid-board-server

verify: bootstrap test
	env DNSID_CLI=$(DNSID_CLI) STATE=$(STATE) REGISTRY_PORT=$(REGISTRY_PORT) DNS_PORT=$(DNS_PORT) \
		PROXY_PORT=$(PROXY_PORT) BOARD_PORT=$(BOARD_PORT) OWNER_PORT=$(OWNER_PORT) \
		POSTER_PORT=$(POSTER_PORT) ZONE=$(ZONE) AUDIENCE=$(AUDIENCE) \
		TOKEN_ENVIRONMENT=$(TOKEN_ENVIRONMENT) bash verify/verify.sh

clean:
	-$(LOCAL) down --state $(STATE)
	rm -rf bin
