# Demo Bank, the sample API the verifier protects, for Cloud Run. Build from this directory (origin/), for Cloud Run's
# platform:
#   docker build --platform linux/amd64 -t <tag> origin
# The build context is only what .dockerignore lets in: package.json, server.ts, LICENSE. It has no dependencies.
#
# Base: the same pinned Node.js 24.22.3 image as the verifier (see ../Dockerfile).
ARG NODE_IMAGE=node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54

FROM ${NODE_IMAGE}
ENV NODE_ENV=production
WORKDIR /app
COPY package.json server.ts LICENSE ./
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["node", "server.ts"]
