# CHIMERA — Docker / netem test harness

A Linux test bed for validating carrier resilience under packet loss. macOS can't
run `tc netem`, and the QUIC/ElasticCC work (Stage 3) lives or dies on its
behaviour under loss — so all loss-path validation runs here.

## What it does

`bench.sh` stands up an isolated topology:

```
client ──carrier(:443)──► server ──plain TCP relay──► target (nginx :80)
   │                         │
   └──── tc netem loss/delay applied on both egress NICs ────┘
```

It then fetches a fixed-size object from `target` through the client's local
SOCKS5 proxy and times the transfer across a sweep of packet-loss rates. The
carrier path carries the emulated loss, so the goodput numbers isolate how the
**carrier transport** copes — which is exactly where TCP-Reality is expected to
collapse and where the QUIC/ElasticCC carrier must hold up.

## Run

```bash
# TCP-Reality baseline (default build):
docker/bench.sh

# QUIC carrier:
TAG=chimera_quic MODE=quic docker/bench.sh

# Shadowsocks-AEAD carrier (ROADMAP2 §3 -- minimal overhead, no ClientHello):
TAG=chimera_ss MODE=ss docker/bench.sh

# DNS-over-TCP carrier (ROADMAP2 §3 -- slower, but blocking it breaks DNS
# for the censor too):
TAG=chimera_dot MODE=dot docker/bench.sh

# Custom sweep / object size:
LOSS="0 30" SIZE_MB=10 docker/bench.sh
```

Knobs (env vars): `LOSS`, `DELAY_MS`, `SIZE_MB`, `MAX_TIME`, `TAG`, `MODE`.

Requires Docker with `NET_ADMIN` capability (granted per-container by the script).
Everything is torn down on exit.

## Build the image directly

⚠ This Dockerfile defaults to **no build tags** on purpose — `bench.sh`'s whole
point is comparing the plain TCP-Reality baseline against QUIC/ElasticCC, so
the untagged build is a deliberate baseline, not an oversight. It is **not**
what you want for an actual deployment. If you're building this image to run
a real server (not to benchmark), always pass the full tag set, the same one
`scripts/build.sh`/`scripts/build.ps1` use for a real binary:

```bash
# Bench baseline (TCP-Reality only, no uTLS/QUIC) — for docker/bench.sh comparisons:
docker build -f docker/Dockerfile -t chimera:bench .

# Real deployment — everything included, same tags as scripts/build.sh:
docker build -f docker/Dockerfile --build-arg TAGS="chimera_utls chimera_quic chimera_netstack chimera_ss chimera_dot" -t chimera:server .
```
