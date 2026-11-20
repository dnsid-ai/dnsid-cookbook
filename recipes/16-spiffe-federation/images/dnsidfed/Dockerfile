# DNSid federation controller (Acme) and binding publisher (Rackloria): one image, two entrypoints.
#
# Python dependencies come from the recipe's uv.lock, exported by `make bootstrap` into
# .state/build/requirements.txt (runtime dependencies plus the `image-build` group):
#   * every PyPI package, including the SDK's build backend, is installed with --require-hashes
#     (binary wheels only);
#   * the dnsid SDK is built from the exact git commit the lock pins (the commit-addressed GitHub source
#     archive, so no git client is needed) with --no-deps --no-build-isolation: its dependencies and
#     build backend are the locked, hash-checked packages above, and nothing else is fetched.
# The spire-server CLI is the unmodified static binary from the pinned SPIRE image; it is used only
# against the organization's own admin socket.
# Base images are pinned by tag and registry index digest.
FROM ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384 AS spire

FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966 AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY .state/build/requirements.txt /tmp/requirements.txt
RUN set -eu; \
    python -m venv /opt/venv; \
    sdk=$(grep -E '^dnsid @ git\+https://github\.com/dnsid-ai/dnsid-py@[0-9a-f]{40}$' /tmp/requirements.txt); \
    commit=${sdk##*@}; \
    grep -vE '^dnsid @ ' /tmp/requirements.txt > /tmp/hashed.txt; \
    /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/hashed.txt; \
    /opt/venv/bin/pip install --no-deps --no-build-isolation \
        "https://github.com/dnsid-ai/dnsid-py/archive/${commit}.tar.gz"

FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
COPY --from=deps /opt/venv /opt/venv
COPY --from=spire /opt/spire/bin/spire-server /usr/local/bin/spire-server
COPY src/dnsidfed /opt/venv/lib/python3.14/site-packages/dnsidfed
WORKDIR /app
ENTRYPOINT ["python", "-I", "-m"]
