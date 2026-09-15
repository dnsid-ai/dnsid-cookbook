.PHONY: new scan-hardcoded-identities test-scan-hardcoded-identities validate-mermaid

new:
	@test -n "$(N)"    || (echo "Usage: make new N=<number> SLUG=<slug>  (e.g. make new N=06 SLUG=http-middleware)" && exit 1)
	@test -n "$(SLUG)" || (echo "Usage: make new N=<number> SLUG=<slug>  (e.g. make new N=06 SLUG=http-middleware)" && exit 1)
	@sh scripts/new-recipe.sh "$(N)" "$(SLUG)"

scan-hardcoded-identities:
	@python3 scripts/scan-hardcoded-identities.py

test-scan-hardcoded-identities:
	@python3 scripts/test_scan_hardcoded_identities.py

validate-mermaid:
	@scripts/validate-mermaid.sh
