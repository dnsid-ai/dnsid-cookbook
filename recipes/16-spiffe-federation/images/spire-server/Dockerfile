# SPIRE server, unchanged upstream binary. Pre-creates the data and admin-socket directories owned by the
# non-root runtime user (1000) so new named volumes inherit that ownership.
# Base images are pinned by tag and registry index digest; refresh with
#   docker buildx imagetools inspect <image:tag>
FROM busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec AS dirs
RUN mkdir -p /out/opt/spire/data/server /out/run/spire/server && chown -R 1000:1000 /out
FROM ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384
COPY --from=dirs --chown=1000:1000 /out/ /
USER 1000:1000
