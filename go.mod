module chimera

go 1.26.4

require (
	github.com/quic-go/quic-go v0.60.0
	github.com/refraction-networking/utls v1.8.2
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20260618175711-3c8c9b1c498a
	modernc.org/sqlite v1.53.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/mobile v0.0.0-20260709172247-6129f5bee9d5 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// ElasticCC patch lives as a local module (formerly a direct edit under vendor/).
// Keeps loss≠congestion CC under our control without re-fetching upstream quic-go.
replace github.com/quic-go/quic-go => ./third_party/quic-go

// Server-side ServerHello templating patch (ROADMAP Этап 1b, JA3S parity) —
// upstream uTLS has no server-side fingerprint API, so this fork adds one.
// Local module, mirrors the quic-go/ElasticCC vendor-fork workflow above.
replace github.com/refraction-networking/utls => ./third_party/utls

tool golang.org/x/mobile/cmd/gobind
