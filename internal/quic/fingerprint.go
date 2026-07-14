//go:build chimera_quic

package quic

import (
	"strings"

	"github.com/quic-go/quic-go"
)

// QUICFingerprintID names a browser QUIC Initial profile. This is the typed
// selection layer for the uquic forward-port: shallow knobs are applied through
// quic-go's public Config today, while frame layout / transport-parameter order
// are carried as metadata for the deeper packet-construction port.
type QUICFingerprintID string

const (
	QUICChromeH3 QUICFingerprintID = "chrome-h3"
)

// QUICFingerprint describes the target Initial fingerprint. TransportParams
// and InitialFrames are documentation/contract metadata only (see
// TestQUICFingerprintCarriesForwardPortContract) — the actual wire behavior
// lives in third_party/quic-go/internal/wire's marshalClientChromeH3, which
// is the source of truth; keep this list in sync with it, not the reverse.
type QUICFingerprint struct {
	ID                QUICFingerprintID
	Aliases           []string
	ALPN              string
	InitialPacketSize uint16
	TransportParams   []string
	InitialFrames     []string
}

var chromeH3Fingerprint = QUICFingerprint{
	ID:                QUICChromeH3,
	Aliases:           []string{"", "chrome", "chrome-h3", "chrome115", "chrome120", "chrome131", "chrome133", "edge"},
	ALPN:              alpn,
	// 1250, not the RFC-typical 1252/1200-round-numbers, per a live capture of
	// real Chrome 150 (stable) against a local test server: three independent
	// captures all showed a consistent 1250-byte UDP payload for every
	// CRYPTO-carrying Initial packet.
	InitialPacketSize: 1250,
	// Real Chrome's parameter set (pcap-derived reference, see
	// third_party/quic-go/internal/wire marshalClientChromeH3): several IETF
	// parameters Chrome never sends are intentionally absent here
	// (ack_delay_exponent, max_ack_delay, disable_active_migration,
	// active_connection_id_limit, reset_stream_at, min_ack_delay), and two
	// Chrome/QUICHE-proprietary parameters are included. The order below is
	// documentation only — the real wire order is freshly randomized per
	// connection, matching Chrome's own per-handshake reshuffle.
	TransportParams: []string{
		"initial_max_stream_data_bidi_local",
		"initial_max_stream_data_bidi_remote",
		"initial_max_stream_data_uni",
		"initial_max_data",
		"initial_max_streams_bidi",
		"initial_max_streams_uni",
		"max_idle_timeout",
		"max_udp_payload_size",
		"max_datagram_frame_size",
		"initial_source_connection_id",
		"version_information",
		"google_connection_options",
		"google_initial_rtt",
	},
	InitialFrames: []string{"crypto", "padding"},
}

func resolveQUICFingerprint(name string) QUICFingerprint {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, alias := range chromeH3Fingerprint.Aliases {
		if n == alias {
			return chromeH3Fingerprint
		}
	}
	return chromeH3Fingerprint
}

func quicConfigForFingerprint(elasticBW uint64, fp QUICFingerprint) *quic.Config {
	cfg := quicConfig(elasticBW)
	if fp.InitialPacketSize >= 1200 {
		cfg.InitialPacketSize = fp.InitialPacketSize
	}
	if fp.ID == QUICChromeH3 {
		cfg.InitialClientHelloProfile = string(fp.ID)
	}
	cfg.InitialCryptoDataTracer = currentInitialCryptoDataTracer()
	if tracer := currentInitialPacketTracer(); tracer != nil {
		cfg.InitialPacketTracer = func(trace quic.InitialPacketTrace) {
			tracer(SummarizeInitialPacketTrace(trace))
		}
	}
	return cfg
}
