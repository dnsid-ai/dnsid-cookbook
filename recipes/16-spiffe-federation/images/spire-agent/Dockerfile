# SPIRE agent, unchanged upstream binary; runs as non-root 1000 (the upstream image defaults to root).
# Data and Workload API socket directories are pre-created and owned by 1000 so named volumes inherit it.
# Base images are pinned by tag and registry index digest; refresh with
#   docker buildx imagetools inspect <image:tag>
FROM busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec AS dirs
RUN mkdir -p /out/opt/spire/data/agent /out/run/spire/agent/public && chown -R 1000:1000 /out
FROM ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481
COPY --from=dirs --chown=1000:1000 /out/ /
USER 1000:1000
