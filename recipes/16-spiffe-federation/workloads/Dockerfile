# Example workloads (go-spiffe v2). One binary; ROLE selects inventory, supplier-api or purchasing.
# Base images are pinned by tag and registry index digest. Runs as a non-root uid set by Compose.
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY main.go ./
RUN go vet ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /workload .

FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
COPY --from=build /workload /usr/local/bin/workload
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/workload"]
