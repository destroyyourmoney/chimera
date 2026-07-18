//go:build chimera_quic

package quic

import (
	"strings"

	"github.com/quic-go/quic-go"
)

type QUICFingerprintID string

const (
	QUICChromeH3 QUICFingerprintID = "chrome-h3"
)

type QUICFingerprint struct {
	ID                QUICFingerprintID
	Aliases           []string
	ALPN              string
	InitialPacketSize uint16
	TransportParams   []string
	InitialFrames     []string
}

var chromeH3Fingerprint = QUICFingerprint{
	ID:      QUICChromeH3,
	Aliases: []string{"", "chrome", "chrome-h3", "chrome115", "chrome120", "chrome131", "chrome133", "edge"},
	ALPN:    alpn,

	InitialPacketSize: 1250,

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
