# CHIMERA test image: builds the chimera binary on Linux and ships it with the
# netem/benchmark tooling (tc, curl) needed to validate carrier resilience under
# packet loss. Build context is the repo root. Defaults to NO build tags on
# purpose -- that's the TCP-Reality baseline docker/bench.sh compares QUIC
# against, not a recommendation. For an actual deployment, always pass the
# same full tag set scripts/build.sh/build.ps1 use for a real binary:
#
#   docker build -f docker/Dockerfile --build-arg TAGS="chimera_utls chimera_quic chimera_ss chimera_dot" -t chimera:server .
#
# Bench-only baseline (see docker/README.md):
#
#   docker build -f docker/Dockerfile -t chimera:bench .

ARG GO_VERSION=1.26.4

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Cache module downloads separately from source changes. third_party/ holds the
# ElasticCC-patched quic-go referenced by the go.mod `replace` directive, so it must
# be present before module resolution / `go mod download`.
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TAGS=""
# CGO off for a static binary that runs in the slim runtime image.
RUN CGO_ENABLED=0 go build -trimpath -tags "${TAGS}" -o /out/chimera ./cmd/chimera

FROM debian:bookworm-slim AS runtime
# iproute2 -> tc/netem, curl -> goodput probes, ca-certificates for TLS egress.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/chimera /usr/local/bin/chimera
ENTRYPOINT ["chimera"]
