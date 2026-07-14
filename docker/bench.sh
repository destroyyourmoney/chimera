#!/usr/bin/env bash
#
# bench.sh — measure CHIMERA carrier goodput under emulated packet loss.
#
# Topology (all on an isolated docker bridge):
#
#   client ──carrier(:443)──► server ──plain TCP relay──► target(nginx :80)
#     │                         │
#     └─ tc netem loss/delay ───┘   (loss applied symmetrically on both egress NICs)
#
# The client runs `chimera proxy` (SOCKS5); we curl a fixed-size object from
# `target` through it and time the transfer. The carrier path (client⇄server)
# carries the emulated loss, so this measures how the carrier transport copes —
# exactly the axis where TCP-Reality is expected to collapse and the QUIC/ElasticCC
# carrier is expected to hold goodput.
#
# Usage:
#   docker/bench.sh                      # default build (TCP carrier), default loss sweep
#   TAG=chimera_quic MODE=quic docker/bench.sh   # build with QUIC carrier, run it
#   LOSS="0 30" SIZE_MB=10 docker/bench.sh       # custom sweep / object size
#
set -euo pipefail

# --- config -----------------------------------------------------------------
IMAGE="${IMAGE:-chimera:bench}"
TAG="${TAG:-}"                       # go build tag, e.g. chimera_quic
MODE="${MODE:-tcp}"                  # carrier mode label for the report (tcp|quic)
NET="${NET:-chimera-bench-net}"
LOSS="${LOSS:-0 20 30 40}"           # percent packet loss values to sweep
DELAY_MS="${DELAY_MS:-15}"           # one-way delay added by netem (each NIC)
SIZE_MB="${SIZE_MB:-20}"            # size of the object fetched through the carrier
MAX_TIME="${MAX_TIME:-180}"         # per-transfer curl timeout (seconds)
WARMUP="${WARMUP:-2}"               # seconds to let proxy/server settle
BW="${BW:-0}"                       # QUIC ElasticCC Brutal target Mbps on server (0 = adaptive)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

c_target="chimera-bench-target"
c_server="chimera-bench-server"
c_client="chimera-bench-client"

# --- cleanup ----------------------------------------------------------------
cleanup() {
  echo "── cleanup ──" >&2
  for c in "$c_client" "$c_server" "$c_target"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- build ------------------------------------------------------------------
echo "── building $IMAGE (tags='$TAG') ──" >&2
docker build -f "$REPO_ROOT/docker/Dockerfile" --build-arg TAGS="$TAG" -t "$IMAGE" "$REPO_ROOT" >&2

# --- network ----------------------------------------------------------------
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

# --- target (nginx serving a fixed-size object) -----------------------------
echo "── starting target (nginx, ${SIZE_MB}MB object) ──" >&2
docker run -d --name "$c_target" --network "$NET" --network-alias target nginx:alpine \
  sh -c "head -c ${SIZE_MB}m /dev/urandom > /usr/share/nginx/html/obj.bin && nginx -g 'daemon off;'" >/dev/null

# --- keys -------------------------------------------------------------------
echo "── generating keys ──" >&2
KEYOUT="$(docker run --rm --entrypoint chimera "$IMAGE" keygen)"
PRIV="$(echo "$KEYOUT" | awk -F': ' '/private/{print $2}' | tr -d ' ')"
PUB="$(echo  "$KEYOUT" | awk -F': ' '/public/ {print $2}' | tr -d ' ')"
[ -n "$PRIV" ] && [ -n "$PUB" ] || { echo "keygen failed:\n$KEYOUT" >&2; exit 1; }

# --- server -----------------------------------------------------------------
echo "── starting server ──" >&2
docker run -d --name "$c_server" --network "$NET" --network-alias server \
  --cap-add NET_ADMIN --entrypoint chimera "$IMAGE" \
  server -listen :443 -steal-host target:80 -priv "$PRIV" -transport "$MODE" -bw "$BW" >/dev/null

# --- client (SOCKS proxy; mode selects the carrier) -------------------------
echo "── starting client proxy (mode=$MODE) ──" >&2
docker run -d --name "$c_client" --network "$NET" \
  --cap-add NET_ADMIN --entrypoint chimera "$IMAGE" \
  proxy -server server:443 -pbk "$PUB" -listen 0.0.0.0:1080 -transport "$MODE" >/dev/null

sleep "$WARMUP"

# --- netem helpers ----------------------------------------------------------
apply_netem() { # $1 = loss percent
  local loss="$1"
  for c in "$c_server" "$c_client"; do
    if [ "$loss" = "0" ]; then
      docker exec "$c" tc qdisc replace dev eth0 root netem delay "${DELAY_MS}ms" >/dev/null 2>&1 || true
    else
      docker exec "$c" tc qdisc replace dev eth0 root netem loss "${loss}%" delay "${DELAY_MS}ms" >/dev/null 2>&1 || true
    fi
  done
}
clear_netem() {
  for c in "$c_server" "$c_client"; do
    docker exec "$c" tc qdisc del dev eth0 root >/dev/null 2>&1 || true
  done
}

# --- sanity: one transfer with no loss --------------------------------------
clear_netem
if ! docker exec "$c_client" curl -s -o /dev/null --max-time 30 \
      --socks5-hostname 127.0.0.1:1080 http://target/obj.bin; then
  echo "FATAL: baseline transfer through carrier failed; dumping logs" >&2
  docker logs "$c_server" 2>&1 | tail -n 20 >&2
  docker logs "$c_client" 2>&1 | tail -n 20 >&2
  exit 1
fi

# --- sweep ------------------------------------------------------------------
printf '\n=== CHIMERA carrier goodput (mode=%s, object=%sMB, delay=%sms/NIC) ===\n' \
  "$MODE" "$SIZE_MB" "$DELAY_MS"
printf '%-8s %-12s %-12s %-10s\n' "loss%" "time(s)" "goodput" "status"
printf '%-8s %-12s %-12s %-10s\n' "-----" "-------" "-------" "------"

for loss in $LOSS; do
  apply_netem "$loss"
  sleep 1
  out="$(docker exec "$c_client" curl -s -o /dev/null \
        --max-time "$MAX_TIME" -w '%{size_download} %{time_total}' \
        --socks5-hostname 127.0.0.1:1080 http://target/obj.bin 2>/dev/null || echo "0 0")"
  size="$(echo "$out" | awk '{print $1}')"
  t="$(echo "$out" | awk '{print $2}')"
  # awk (not bc — not reliably present, e.g. stock Git-for-Windows/MSYS bash)
  # does both the float comparison and the MB/s calculation in one pass.
  if [ "${size:-0}" -gt 0 ] && awk -v t="${t:-0}" 'BEGIN { exit !(t > 0) }'; then
    mbps="$(awk -v s="$size" -v t="$t" 'BEGIN { printf "%.2f", s / 1048576 / t }')"
    printf '%-8s %-12s %-12s %-10s\n' "$loss" "$t" "${mbps} MB/s" "ok"
  else
    printf '%-8s %-12s %-12s %-10s\n' "$loss" ">${MAX_TIME}" "—" "timeout"
  fi
  clear_netem
done

echo
echo "Done. (TCP-Reality is expected to degrade sharply with loss; that gap is the"
echo " baseline the QUIC/ElasticCC carrier must close.)"
