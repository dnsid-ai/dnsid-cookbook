.PHONY: bootstrap run verify test clean

bootstrap:
	npm ci
	node test/e2e/recipe.ts bootstrap

run: bootstrap
	npm run build:check
	node test/e2e/recipe.ts run

verify: bootstrap
	npm run typecheck
	npm test
	npm run build:check
	node test/e2e/recipe.ts run

test:
	npm ci
	npm run typecheck
	npm test

clean:
	node test/e2e/recipe.ts clean
	rm -rf .out .wrangler
