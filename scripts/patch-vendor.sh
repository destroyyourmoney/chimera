#!/usr/bin/env bash
# patch-vendor.sh — (re)apply CHIMERA patches to the vendored quic-go after
# running `go mod vendor`. Run this whenever you update quic-go or re-vendor.
#
# Patches applied:
#   1. Config.UseElasticCC bool field
#   2. NewSentPacketHandler accepts useElasticCC bool
#   3. MigratedPath preserves CC type
#   4. elastic.go — ElasticCC implementation
#   5. elastic_test.go — ElasticCC unit tests
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
QGO="$REPO/vendor/github.com/quic-go/quic-go"

echo "▶ patching quic-go in $QGO"

# ── 1. interface.go: add UseElasticCC to Config ────────────────────────────
python3 - <<'PY' "$QGO/interface.go"
import sys, re
path = sys.argv[1]
src = open(path).read()
OLD = '\tEnableStreamResetPartialDelivery bool\n\n\tTracer func'
NEW = '''\tEnableStreamResetPartialDelivery bool

\t// UseElasticCC replaces the default Cubic congestion controller with ElasticCC:
\t// a rate-based sender where packet loss does NOT trigger a congestion window cut.
\t// Designed for adversarial-loss environments (DPI throttling, GFW) where loss
\t// is not a signal of buffer overflow but of deliberate packet dropping.
\tUseElasticCC bool

\tTracer func'''
assert OLD in src, "patch point not found in interface.go"
open(path, 'w').write(src.replace(OLD, NEW, 1))
print("  ✓ interface.go")
PY

# ── 2. connection.go: pass UseElasticCC to NewSentPacketHandler (both sites) ─
python3 - <<'PY' "$QGO/connection.go"
import sys
path = sys.argv[1]
src = open(path).read()
OLD = '\t\ts.qlogger,\n\t\ts.logger,\n\t)\n\ts.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))\n\tstatelessResetToken'
NEW = '\t\ts.qlogger,\n\t\ts.logger,\n\t\ts.config.UseElasticCC,\n\t)\n\ts.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))\n\tstatelessResetToken'
count = src.count(OLD)
assert count >= 1, f"first patch point not found in connection.go (got {count})"
src = src.replace(OLD, NEW, 1)

OLD2 = '\t\ts.qlogger,\n\t\ts.logger,\n\t)\n\ts.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))\n\toneRTTStream'
NEW2 = '\t\ts.qlogger,\n\t\ts.logger,\n\t\ts.config.UseElasticCC,\n\t)\n\ts.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))\n\toneRTTStream'
assert OLD2 in src, "second patch point not found in connection.go"
src = src.replace(OLD2, NEW2, 1)
open(path, 'w').write(src)
print("  ✓ connection.go")
PY

# ── 3. sent_packet_handler.go: inject ElasticCC ──────────────────────────────
python3 - <<'PY' "$QGO/internal/ackhandler/sent_packet_handler.go"
import sys
path = sys.argv[1]
src = open(path).read()

# Add useElasticCC field to struct
OLD_STRUCT = '\tcongestion congestion.SendAlgorithmWithDebugInfos\n\trttStats   *utils.RTTStats'
NEW_STRUCT = '\tcongestion   congestion.SendAlgorithmWithDebugInfos\n\tuseElasticCC bool\n\trttStats     *utils.RTTStats'
assert OLD_STRUCT in src, "struct field patch point not found"
src = src.replace(OLD_STRUCT, NEW_STRUCT, 1)

# Add useElasticCC param + dispatch
OLD_FUNC = '''\tlogger utils.Logger,
) SentPacketHandler {
\tcongestion := congestion.NewCubicSender(
\t\tcongestion.DefaultClock{},
\t\trttStats,
\t\tconnStats,
\t\tinitialMaxDatagramSize,
\t\ttrue, // use Reno
\t\tqlogger,
\t)

\th := &sentPacketHandler{'''
NEW_FUNC = '''\tlogger utils.Logger,
\tuseElasticCC bool,
) SentPacketHandler {
\tvar cc congestion.SendAlgorithmWithDebugInfos
\tif useElasticCC {
\t\tcc = congestion.NewElasticSender(congestion.DefaultClock{}, rttStats, initialMaxDatagramSize)
\t} else {
\t\tcc = congestion.NewCubicSender(
\t\t\tcongestion.DefaultClock{},
\t\t\trttStats,
\t\t\tconnStats,
\t\t\tinitialMaxDatagramSize,
\t\t\ttrue, // use Reno
\t\t\tqlogger,
\t\t)
\t}

\th := &sentPacketHandler{'''
assert OLD_FUNC in src, "func signature patch point not found"
src = src.replace(OLD_FUNC, NEW_FUNC, 1)

# Fix struct initializer: congestion: congestion → cc + add useElasticCC field
OLD_INIT = '\t\tcongestion:                     congestion,\n\t\tignorePacketsBelow:'
NEW_INIT = '\t\tcongestion:                     cc,\n\t\tuseElasticCC:                   useElasticCC,\n\t\tignorePacketsBelow:'
assert OLD_INIT in src, "struct init patch point not found"
src = src.replace(OLD_INIT, NEW_INIT, 1)

# Fix MigratedPath
OLD_MIGR = '''\th.congestion = congestion.NewCubicSender(
\t\tcongestion.DefaultClock{},
\t\th.rttStats,
\t\th.connStats,
\t\tinitialMaxDatagramSize,
\t\ttrue, // use Reno
\t\th.qlogger,
\t)
\th.setLossDetectionTimer(now)'''
NEW_MIGR = '''\tif h.useElasticCC {
\t\th.congestion = congestion.NewElasticSender(congestion.DefaultClock{}, h.rttStats, initialMaxDatagramSize)
\t} else {
\t\th.congestion = congestion.NewCubicSender(
\t\t\tcongestion.DefaultClock{},
\t\t\th.rttStats,
\t\t\th.connStats,
\t\t\tinitialMaxDatagramSize,
\t\t\ttrue, // use Reno
\t\t\th.qlogger,
\t\t)
\t}
\th.setLossDetectionTimer(now)'''
assert OLD_MIGR in src, "MigratedPath patch point not found"
src = src.replace(OLD_MIGR, NEW_MIGR, 1)

open(path, 'w').write(src)
print("  ✓ sent_packet_handler.go")
PY

# ── 4 & 5. Copy elastic.go and elastic_test.go ───────────────────────────────
CONG="$QGO/internal/congestion"
cp "$REPO/scripts/elastic.go.tpl"      "$CONG/elastic.go"      2>/dev/null || true
cp "$REPO/scripts/elastic_test.go.tpl" "$CONG/elastic_test.go" 2>/dev/null || true

echo "▶ verifying build"
cd "$REPO"
go build -mod=vendor ./...
go build -mod=vendor -tags chimera_quic ./...
echo "✅ all patches applied and build verified"
