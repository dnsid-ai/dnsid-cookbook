#!/bin/sh
# Scaffold a new local-registry recipe: Makefile (bootstrap/run/verify/clean),
# pyproject.toml, src/, verify/verify.sh, .gitignore, and a README skeleton.
# The shape generalizes recipes 12 and 31 — see RECIPE_TEMPLATE.md for the
# authoring rules.
set -e

N="$1"
SLUG="$2"

if [ -z "$N" ] || [ -z "$SLUG" ]; then
    echo "Usage: make new N=<number> SLUG=<slug>"
    echo "  Example: make new N=13 SLUG=grpc-channel-auth"
    exit 1
fi

DIR="recipes/${N}-${SLUG}"
# The agent's short name (also its local registry identity name). Derived from the
# slug; override by editing the generated Makefile.
AGENT=$(printf '%s' "$SLUG" | cut -d- -f1)
DOMAIN="${AGENT}.dev.dnsid.test"
PORT=3301

if [ -d "$DIR" ]; then
    echo "Error: $DIR already exists"
    exit 1
fi

echo "Creating $DIR..."
mkdir -p "${DIR}/src" "${DIR}/verify"

# --- Makefile ---
cat > "${DIR}/Makefile" <<EOF
.PHONY: bootstrap run verify clean

DNSID_CLI ?= dnsid
ZONE ?= dev.dnsid.test
AGENT := ${AGENT}
DOMAIN := \$(AGENT).\$(ZONE)
PORT ?= ${PORT}

# Start the local registry and provision the identity. Idempotent: \`agent ensure\`
# and \`log issue\` are safe to re-run for existing identities.
bootstrap:
	\$(DNSID_CLI) local up
	\$(DNSID_CLI) local agent ensure \$(AGENT) --upstream http://localhost:\$(PORT) -- \\
		\$(DNSID_CLI) log issue --domain \$(DOMAIN)
	uv sync

# The flow, human-watchable. Same script as \`make verify\`, without assertions.
run: bootstrap
	DNSID_RECIPE_ASSERT=0 bash verify/verify.sh

# One-shot: run the flow and assert the expected transcript; nonzero on failure.
verify: bootstrap
	bash verify/verify.sh

clean:
	\$(DNSID_CLI) local down
EOF

# --- pyproject.toml ---
cat > "${DIR}/pyproject.toml" <<EOF
[project]
name = "recipe-${N}-${SLUG}"
version = "0.1.0"
description = "DNSid cookbook recipe ${N} — ${SLUG}"
requires-python = ">=3.11"
# Pin the versions you actually test against before merging.
dependencies = [
    # The dnsid SDK is not yet on PyPI; install from a release tag.
    "dnsid @ git+https://github.com/dnsid-ai/dnsid-py@v0.19.1",
]
EOF

# --- src/main.py ---
cat > "${DIR}/src/main.py" <<EOF
#!/usr/bin/env python3
"""Recipe ${N} entry point.

Run under the local registry so the DNSID_* environment is injected:

    dnsid local run ${AGENT} --upstream http://localhost:${PORT} -- \\
        uv run python -u src/main.py

Start from recipe 12's src/ for the identity lifecycle (registration,
challenge, publish, self-verify) and ingress middleware, and recipe 31's
src/dnsid_identity/ for signed egress.
"""

import os


def main() -> None:
    domain = os.environ.get("DNSID_DOMAIN", "")
    if not domain:
        raise SystemExit("DNSID_DOMAIN is not set; run via \`dnsid local run\`")
    print(f"hello from {domain}")


if __name__ == "__main__":
    main()
EOF

# --- verify/verify.sh ---
cat > "${DIR}/verify/verify.sh" <<EOF
#!/usr/bin/env bash
# One-shot run of the recipe flow, with transcript assertions.
# DNSID_RECIPE_ASSERT=0 skips the assertions (used by \`make run\`).
# Assumes \`make bootstrap\` has run (local registry up, identities ensured).
set -euo pipefail
cd "\$(dirname "\$0")/.."

DNSID_CLI="\${DNSID_CLI:-dnsid}"
ZONE="\${ZONE:-dev.dnsid.test}"
PORT="\${PORT:-${PORT}}"
ASSERT="\${DNSID_RECIPE_ASSERT:-1}"

# Portable across BSD and GNU mktemp: an explicit XXXXXX template.
LOG=\$(mktemp "\${TMPDIR:-/tmp}/dnsid-recipe${N}.XXXXXX")

fail() {
    echo "" >&2
    echo "FAIL: \$1" >&2
    # Emit the local registry container logs — a red CI job without them is undebuggable.
    docker ps --filter "name=dnsid-local" >&2 || true
    docker ps -q --filter "name=dnsid-local" | while read -r c; do
        echo "--- docker logs \${c} (tail) ---" >&2
        docker logs --tail 50 "\${c}" >&2 || true
    done
    exit 1
}

cleanup() {
    # \`dnsid local run\` wraps the python process; kill by command line.
    pkill -f "python -u src/main.py" 2>/dev/null || true
    rm -f "\${LOG}"
}
trap cleanup EXIT

# Note: \`python -u\` matters — verify scripts grep process output, and Python
# buffers stdout when piped.
"\${DNSID_CLI}" local run ${AGENT} --upstream "http://localhost:\${PORT}" -- \\
    uv run python -u src/main.py \\
    2>&1 | tee "\${LOG}"

if [[ "\${ASSERT}" == "1" ]]; then
    echo ""
    echo "==> asserting transcript"
    grep -q "hello from ${DOMAIN}" "\${LOG}" \\
        || fail "expected transcript line missing"
    echo "  ok: recipe ran under its local registry identity"
    echo ""
    echo "✓ verify passed"
fi
EOF
chmod +x "${DIR}/verify/verify.sh"

# --- .gitignore ---
cat > "${DIR}/.gitignore" <<EOF
.venv/
__pycache__/
EOF

# --- README.md skeleton ---
cat > "${DIR}/README.md" <<EOF
# Recipe ${N} — TITLE

> One-sentence tagline. Same line that appears in INDEX.md.

**Spec version:** \`dnsid-draft-01\`
**Status:** runnable
**Standards used:** …
**Estimated time:** ~N minutes

---

## What you'll build

## Why this matters

## Prerequisites

- Docker 24+ (running)
- \`make\`
- The \`dnsid\` CLI — \`brew install dnsid-ai/tap/dnsid\`, or download a binary per the [installation docs](https://docs.dnsid.ai/cli-installation) and put it on \`PATH\`
- [\`uv\`](https://docs.astral.sh/uv/) 0.12+
- A clone of this repo

## Concepts

## Running system

| Process | Where | Role |
|---|---|---|
| DNS server | local registry container, \`127.0.0.1:7753\` | Serves live \`_dnsid.*.dev.dnsid.test\` TXT records |
| Registry + transparency log | local registry container, \`127.0.0.1:7755\` | Registration, challenge verification, publication, C2SP log |
| TLS proxy | local registry container | Terminates \`https://*.dev.dnsid.test\` with a local CA |
| ${AGENT} | host process, \`:${PORT}\` | … |

## Step 1 — …

## Run it

\`\`\`bash
make run
\`\`\`

## Verify

\`\`\`bash
make verify
\`\`\`

## What to try next

## Glossary
EOF

echo "Created ${DIR}"
echo ""
echo "Next steps:"
echo "  1. Fill in ${DIR}/README.md following RECIPE_TEMPLATE.md (see the"
echo "     'Notes for recipe authors' section for the harness contract)."
echo "  2. Build the recipe in ${DIR}/src/ — recipes 12 and 31 are the"
echo "     reference implementations."
echo "  3. Add real assertions to ${DIR}/verify/verify.sh."
echo "  4. Add the recipe to INDEX.md and to the CI matrix in"
echo "     .github/workflows/verify-recipes.yml in the same PR."
echo "  5. cd ${DIR} && make bootstrap && make verify"
