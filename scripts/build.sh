#!/usr/bin/env bash
# Builds the one chimera binary you actually want to run: every optional
# feature compiled in (uTLS Chrome ClientHello fingerprint, QUIC/ElasticCC
# carrier, TUN/netstack full-tunnel). There is no reason to pick a smaller tag
# set for a real deployment -- each tag only gates an additional feature, never
# removes one, and a server built with fewer tags than a client (or vice
# versa) will refuse to negotiate the modes it wasn't built with (error:
# "rebuild with -tags chimera_quic"). The per-tag commands in README.md are for
# contributors verifying that each feature still builds/tests in isolation,
# not a menu of build options to choose between.
set -euo pipefail
cd "$(dirname "$0")/.."

TAGS="chimera_utls chimera_quic chimera_netstack"
CGO_ENABLED=0 go build -buildvcs=false -tags "$TAGS" -o bin/chimera ./cmd/chimera

echo "Built bin/chimera (tags: $TAGS)."
