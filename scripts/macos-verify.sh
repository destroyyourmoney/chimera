#!/usr/bin/env bash
#
# macos-verify.sh — native end-to-end smoke test of the CHIMERA carrier on a
# single macOS host. No Docker, no root, no remote server: it builds the binary,
# stands up a local HTTP target + carrier server + SOCKS5 proxy on loopback, and
# pulls a fixed-size object through the carrier for each transport, verifying the
# bytes round-trip exactly (sha256) and reporting rough goodput.
#
# This proves the protocol works end-to-end live (handshake → auth → tunnel →
# QUIC/FEC → SOCKS relay). For goodput UNDER PACKET LOSS, use docker/bench.sh:
# emulating loss on macOS loopback is unreliable (pf skips lo0), so loss testing
# belongs in the Linux/netem harness, not here.
#
# Usage:
#   scripts/macos-verify.sh                       # tcp, quic, quic-rudp; 10 MB
#   TRANSPORTS="quic-rudp" SIZE_MB=50 scripts/macos-verify.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- config -----------------------------------------------------------------
TRANSPORTS="${TRANSPORTS:-tcp quic quic-rudp}"
SIZE_MB="${SIZE_MB:-10}"
SERVER_PORT="${SERVER_PORT:-18443}"
SOCKS_PORT="${SOCKS_PORT:-11080}"
TARGET_PORT="${TARGET_PORT:-18088}"
WARMUP="${WARMUP:-1}"          # seconds to let server/proxy settle
MAX_TIME="${MAX_TIME:-120}"    # per-transfer curl timeout

# This project's Go toolchain is not on PATH (see project memory); override via GO/PATH.
export PATH="${LOCAL_GO_BIN:-$HOME/.local-go/go/bin}:$PATH"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
GO="${GO:-go}"

WORK="$(mktemp -d -t chimera-verify)"
BIN="$WORK/chimera"
declare -a PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

log() { printf '── %s\n' "$*" >&2; }

# --- preflight --------------------------------------------------------------
command -v "$GO" >/dev/null 2>&1 || { echo "FATAL: go not found (set GO= or LOCAL_GO_BIN=)" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 required for the local HTTP target" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "FATAL: curl required" >&2; exit 1; }

# --- build (chimera_quic enables the quic + quic-rudp transports) ------------
log "building chimera (-tags chimera_quic)"
"$GO" build -tags chimera_quic -o "$BIN" ./cmd/chimera

# --- keys -------------------------------------------------------------------
log "generating keys"
KEYOUT="$("$BIN" keygen)"
PRIV="$(printf '%s\n' "$KEYOUT" | awk -F'[: ]+' '/private/{print $NF}')"
PUB="$(printf '%s\n'  "$KEYOUT" | awk -F'[: ]+' '/public/{print $NF}')"
[ -n "$PRIV" ] && [ -n "$PUB" ] || { echo "FATAL: keygen failed:" >&2; echo "$KEYOUT" >&2; exit 1; }

# --- target: a local HTTP server serving a fixed-size random object ----------
SRVDIR="$WORK/www"
mkdir -p "$SRVDIR"
dd if=/dev/urandom of="$SRVDIR/obj.bin" bs=1m count="$SIZE_MB" >/dev/null 2>&1
SRC_SHA="$(shasum -a 256 "$SRVDIR/obj.bin" | awk '{print $1}')"
log "target object: ${SIZE_MB} MB  sha256=${SRC_SHA:0:16}…"
python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 --directory "$SRVDIR" >/dev/null 2>&1 &
PIDS+=($!)
sleep 1

LAST_PID=""
start_proc() { # $@ = chimera args; records pid in LAST_PID + PIDS, tees log
  "$BIN" "$@" >"$WORK/last.log" 2>&1 &
  LAST_PID=$!
  PIDS+=("$LAST_PID")
}

wait_port() { # $1=host:port  $2=timeout-s
  local hp="$1" t="${2:-5}" i=0
  until nc -z "${hp%:*}" "${hp#*:}" >/dev/null 2>&1; do
    i=$((i+1)); [ "$i" -ge "$((t*5))" ] && return 1; sleep 0.2
  done
}

# --- run each transport -----------------------------------------------------
printf '\n=== CHIMERA macOS loopback verify (object=%sMB) ===\n' "$SIZE_MB"
printf '%-12s %-10s %-12s %-10s\n' "transport" "time(s)" "goodput" "result"
printf '%-12s %-10s %-12s %-10s\n' "---------" "-------" "-------" "------"

overall_ok=1
for T in $TRANSPORTS; do
  # fresh server + proxy per transport
  start_proc server -listen ":$SERVER_PORT" -priv "$PRIV" -steal-host "127.0.0.1:$TARGET_PORT" -transport "$T"
  SRV_PID=$LAST_PID
  # QUIC listens on UDP (no TCP-connect probe possible), so check the process is
  # alive rather than port-probing; curl drives the real dial below.
  sleep "$WARMUP"
  if ! kill -0 "$SRV_PID" 2>/dev/null; then
    printf '%-12s %-10s %-12s %-10s\n' "$T" "-" "-" "server-down"; overall_ok=0
    tail -n 15 "$WORK/last.log" >&2; continue
  fi
  start_proc proxy -server "127.0.0.1:$SERVER_PORT" -pbk "$PUB" -listen "127.0.0.1:$SOCKS_PORT" -transport "$T"
  PRX_PID=$LAST_PID
  wait_port "127.0.0.1:$SOCKS_PORT" 5 || true # SOCKS listener is TCP, probe works
  sleep "$WARMUP"

  out="$(curl -s -o "$WORK/out.bin" --max-time "$MAX_TIME" \
        -w '%{size_download} %{time_total}' \
        --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        "http://127.0.0.1:$TARGET_PORT/obj.bin" 2>/dev/null || echo "0 0")"
  size="$(echo "$out" | awk '{print $1}')"; t="$(echo "$out" | awk '{print $2}')"
  got_sha="$(shasum -a 256 "$WORK/out.bin" 2>/dev/null | awk '{print $1}')"

  if [ "${size:-0}" -gt 0 ] && [ "$got_sha" = "$SRC_SHA" ]; then
    mbps="$(echo "scale=2; $size/1048576/$t" | bc -l 2>/dev/null || echo '?')"
    printf '%-12s %-10s %-12s %-10s\n' "$T" "$t" "${mbps} MB/s" "PASS"
  else
    printf '%-12s %-10s %-12s %-10s\n' "$T" "${t:-?}" "—" "FAIL"
    overall_ok=0; tail -n 15 "$WORK/last.log" >&2
  fi

  kill "$PRX_PID" "$SRV_PID" 2>/dev/null || true
  sleep 0.3
done

echo
if [ "$overall_ok" = "1" ]; then
  echo "OK — carrier verified byte-exact over loopback for: $TRANSPORTS"
else
  echo "FAIL — see logs above"; exit 1
fi
