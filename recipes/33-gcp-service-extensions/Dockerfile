# The verifier (the ext_proc callout service) for Cloud Run. Build from this directory, for Cloud Run's platform:
#   docker build --platform linux/amd64 -t <tag> .
# The build context is only what .dockerignore lets in: package.json, package-lock.json, .npmrc, LICENSE, src/, proto/.
#
# Base: the official Node.js image, Node 24.22.3 on Debian bookworm-slim, pinned by its multi-platform index digest
# (resolved 2026-11-12; linux/amd64 manifest sha256:0e2646ab57e77b7a384a0cb59b6815b182c77e1f9c3ba36bd8435bd9c4e6680e).
ARG NODE_IMAGE=node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54

FROM ${NODE_IMAGE} AS install
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
# Production dependencies exactly as the lockfile pins them; no install scripts run.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force

FROM ${NODE_IMAGE}
ENV NODE_ENV=production
WORKDIR /app
COPY --from=install /app/node_modules ./node_modules
COPY package.json LICENSE ./
COPY proto ./proto
COPY src ./src
# The image's own unprivileged user (node, uid 1000). Files stay owned by root, so the service can't change them.
USER 1000:1000
# Cloud Run sets PORT (8080 by default); the service listens on 0.0.0.0 at it, in plaintext HTTP/2.
EXPOSE 8080
# Exec form: node is PID 1 and receives SIGTERM itself, then shuts down within its grace period.
ENTRYPOINT ["node", "src/main.ts"]
