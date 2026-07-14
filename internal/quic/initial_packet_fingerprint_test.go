//go:build chimera_quic

package quic

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"chimera/internal/carrier"
)

// TestChromeH3InitialSpansMultiplePackets locks in a discovery made while
// investigating whether "2-datagram Initial splitting" (real Chrome's
// post-quantum ClientHello, ~1.7-1.9KB, doesn't fit one QUIC Initial payload
// and spans 2 UDP datagrams) needed dedicated packet_packer.go work: it does
// not. CHIMERA's chrome-h3 ClientHello (HelloChrome_133 + a genuine
// X25519MLKEM768 key share) is already large enough to not fit one Initial
// packet, and quic-go's existing, unmodified CRYPTO-stream fragmentation
// already splits it across multiple Initial packets — each one still
// carrying CRYPTO frame(s) before trailing PADDING, and each still using
// Chrome's fixed connection-ID shape (8-byte DCID, zero-length SCID). This
// test guards that behavior so a future change to the ClientHello size or
// the packer doesn't silently collapse back to a single (non-Chrome-shaped,
// truncated) packet without anyone noticing.
func TestChromeH3InitialSpansMultiplePackets(t *testing.T) {
	addr, pub := startServer(t)

	var (
		mu      sync.Mutex
		packets []InitialPacketSummary
	)
	restorePacket := SetInitialPacketTracer(func(s InitialPacketSummary) {
		mu.Lock()
		packets = append(packets, s)
		mu.Unlock()
	})
	defer restorePacket()

	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: "example.com", Transport: "quic", Fp: "chrome-h3"}
	if err := Ping(cfg); err != nil {
		t.Fatalf("ping over quic carrier: %v", err)
	}

	mu.Lock()
	got := append([]InitialPacketSummary(nil), packets...)
	mu.Unlock()

	cryptoPackets := 0
	for _, p := range got {
		if !slices.Contains(p.Frames, "crypto") {
			continue
		}
		cryptoPackets++
		if p.DestConnIDLen != 8 {
			t.Fatalf("CRYPTO-carrying Initial packet dcid length = %d, want 8", p.DestConnIDLen)
		}
		if p.SrcConnIDLen != 0 {
			t.Fatalf("CRYPTO-carrying Initial packet scid length = %d, want 0", p.SrcConnIDLen)
		}
		assertInitialFramesCryptoBeforePadding(t, p.Frames)
	}
	if cryptoPackets < 2 {
		t.Fatalf("got %d CRYPTO-carrying Initial packets, want >=2 (chrome-h3 ClientHello should span multiple Initial packets)", cryptoPackets)
	}
}

// TestChromeH3InitialCryptoFragmentedWithPING locks in the CRYPTO/PING
// frame-fragmentation fix from a live Chrome 150 capture (see
// docs/uquic-initial-fingerprint.md, increment 10): real Chrome fragments
// its Initial CRYPTO data into several small frames interspersed with PING
// frames, not one or two large CRYPTO frames — which was itself a
// distinguishing signal (see packChromeH3InitialCryptoFrames in
// third_party/quic-go/packet_packer.go). This asserts at least one
// CRYPTO-carrying Initial packet contains a PING frame and more than one
// CRYPTO frame, so a future change can't silently collapse the
// fragmentation back to the old "big CRYPTO + PADDING" shape.
func TestChromeH3InitialCryptoFragmentedWithPING(t *testing.T) {
	addr, pub := startServer(t)

	var (
		mu      sync.Mutex
		packets []InitialPacketSummary
	)
	restorePacket := SetInitialPacketTracer(func(s InitialPacketSummary) {
		mu.Lock()
		packets = append(packets, s)
		mu.Unlock()
	})
	defer restorePacket()

	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: "example.com", Transport: "quic", Fp: "chrome-h3"}
	if err := Ping(cfg); err != nil {
		t.Fatalf("ping over quic carrier: %v", err)
	}

	mu.Lock()
	got := append([]InitialPacketSummary(nil), packets...)
	mu.Unlock()

	sawPING := false
	sawMultipleCryptoFrames := false
	for _, p := range got {
		if !slices.Contains(p.Frames, "crypto") {
			continue
		}
		assertInitialFramesCryptoBeforePadding(t, p.Frames)
		if slices.Contains(p.Frames, "ping") {
			sawPING = true
		}
		cryptoCount := 0
		for _, f := range p.Frames {
			if f == "crypto" {
				cryptoCount++
			}
		}
		if cryptoCount > 1 {
			sawMultipleCryptoFrames = true
		}
	}
	if !sawPING {
		t.Fatalf("no PING frame seen in any CRYPTO-carrying Initial packet, want Chrome-shaped fragmentation")
	}
	if !sawMultipleCryptoFrames {
		t.Fatalf("no Initial packet had more than one CRYPTO frame, want Chrome-shaped fragmentation")
	}
}

func TestChromeH3InitialPacketFingerprintHarness(t *testing.T) {
	addr, pub := startServer(t)
	const sni = "example.com"
	gotCrypto := make(chan []byte, 1)
	gotPacket := make(chan InitialPacketSummary, 1)
	restoreCrypto := SetInitialCryptoDataTracer(func(p []byte) {
		select {
		case gotCrypto <- p:
		default:
		}
	})
	defer restoreCrypto()
	restorePacket := SetInitialPacketTracer(func(s InitialPacketSummary) {
		select {
		case gotPacket <- s:
		default:
		}
	})
	defer restorePacket()

	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: sni, Transport: "quic", Fp: "chrome-h3"}
	if err := Ping(cfg); err != nil {
		t.Fatalf("ping over quic carrier: %v", err)
	}

	var packet InitialPacketSummary
	select {
	case packet = <-gotPacket:
	case <-time.After(3 * time.Second):
		t.Fatal("Initial packet tracer was not called")
	}
	want := InitialPacketSummary{
		Version:         quic.Version1,
		TokenLen:        0,
		PacketNumber:    0,
		Length:          int(chromeH3Fingerprint.InitialPacketSize),
		Frames:          packet.Frames,
		PacketNumberLen: packet.PacketNumberLen,
		DestConnIDLen:   packet.DestConnIDLen,
		SrcConnIDLen:    packet.SrcConnIDLen,
	}
	if diffs := DiffInitialPacketSummaries(packet, want); len(diffs) != 0 {
		t.Fatalf("Initial packet summary differs from Chrome-H3 contract: %+v", diffs)
	}
	if len(packet.Packet) != packet.Length {
		t.Fatalf("packet bytes length = %d, summary length = %d", len(packet.Packet), packet.Length)
	}
	parsedPacket, err := SummarizeInitialPacket(packet.Packet)
	if err != nil {
		t.Fatalf("parse traced Initial packet bytes: %v", err)
	}
	if parsedPacket.Version != packet.Version ||
		parsedPacket.Length != packet.Length ||
		parsedPacket.DestConnIDLen != packet.DestConnIDLen ||
		parsedPacket.SrcConnIDLen != packet.SrcConnIDLen ||
		parsedPacket.TokenLen != packet.TokenLen {
		t.Fatalf("parsed packet summary = %+v, trace summary = %+v", parsedPacket, packet)
	}
	// Real Chrome uses a fixed 8-byte DCID guess and a zero-length client
	// SCID (pcap-derived reference); both are asserted exactly, not just
	// bounded, since a wrong-but-in-range value is still a mismatch.
	if packet.DestConnIDLen != 8 {
		t.Fatalf("dcid length = %d, want 8 (Chrome's fixed Initial DCID length)", packet.DestConnIDLen)
	}
	if packet.SrcConnIDLen != 0 {
		t.Fatalf("scid length = %d, want 0 (Chrome's zero-length client SCID)", packet.SrcConnIDLen)
	}
	assertInitialFramesCryptoBeforePadding(t, packet.Frames)

	var cryptoRaw []byte
	select {
	case cryptoRaw = <-gotCrypto:
	case <-time.After(3 * time.Second):
		t.Fatal("Initial CRYPTO tracer was not called")
	}
	hello, err := SummarizeClientHello(cryptoRaw)
	if err != nil {
		t.Fatalf("summarize current ClientHello: %v", err)
	}
	if hello.SNI != sni {
		t.Fatalf("SNI = %q, want %q", hello.SNI, sni)
	}
	if !slices.Equal(hello.ALPN, []string{alpn}) {
		t.Fatalf("ALPN = %v, want [%s]", hello.ALPN, alpn)
	}
	assertTransportParameterOrder(t, hello.QUICParams)
}

// assertInitialFramesCryptoBeforePadding checks the Chrome-shaped Initial
// frame layout: CRYPTO frames interspersed with PING frames (real Chrome
// fragments its Initial CRYPTO data into many small frames with PING
// interleaved — see packChromeH3InitialCryptoFrames in
// third_party/quic-go/packet_packer.go and docs/uquic-initial-fingerprint.md
// increment 10), followed by trailing PADDING. It does not require at least
// one CRYPTO frame, since an ACK-only Initial packet (no CRYPTO frame at
// all, e.g. crypto/ping/padding-less "ack" packets) legitimately has a
// different shape and is not passed to this helper by callers.
func assertInitialFramesCryptoBeforePadding(t *testing.T, frames []string) {
	t.Helper()
	if len(frames) < 2 {
		t.Fatalf("Initial frames = %v, want crypto/ping frame(s) followed by padding", frames)
	}
	if frames[len(frames)-1] != "padding" {
		t.Fatalf("Initial frames = %v, want trailing padding", frames)
	}
	for _, frame := range frames[:len(frames)-1] {
		if frame != "crypto" && frame != "ping" {
			t.Fatalf("Initial frames = %v, want only crypto/ping before padding", frames)
		}
	}
}

// assertTransportParameterOrder asserts the chrome-h3 transport-parameter
// *set*: real Chrome reshuffles the parameter order on every handshake (see
// third_party/quic-go/internal/wire/transport_parameters.go
// marshalClientChromeH3), so a fixed relative order is not itself a valid
// fingerprint target — only the parameter set is checked here.
func assertTransportParameterOrder(t *testing.T, ids []uint64) {
	t.Helper()
	ids = stripGREASETransportParameterIDs(ids)
	present := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		present[id] = true
	}
	required := []uint64{
		0x04,   // initial_max_data
		0x05,   // initial_max_stream_data_bidi_local
		0x06,   // initial_max_stream_data_bidi_remote
		0x07,   // initial_max_stream_data_uni
		0x08,   // initial_max_streams_bidi
		0x09,   // initial_max_streams_uni
		0x01,   // max_idle_timeout
		0x03,   // max_udp_payload_size
		0x0f,   // initial_source_connection_id
		0x20,   // max_datagram_frame_size
		0x11,   // version_information
		0x3127, // google_initial_rtt
		0x3128, // google_connection_options
	}
	for _, want := range required {
		if !present[want] {
			t.Fatalf("transport parameter set %x is missing required id 0x%x", ids, want)
		}
	}
	forbidden := []uint64{
		0x0a,             // ack_delay_exponent
		0x0b,             // max_ack_delay
		0x0c,             // disable_active_migration
		0x0e,             // active_connection_id_limit
		0x17f7586d2cb571, // reset_stream_at
		0xff04de1b,       // min_ack_delay
	}
	for _, unwanted := range forbidden {
		if present[unwanted] {
			t.Fatalf("transport parameter set %x contains id 0x%x, which real Chrome never sends", ids, unwanted)
		}
	}
}

func stripGREASETransportParameterIDs(ids []uint64) []uint64 {
	out := ids[:0]
	for _, id := range ids {
		if id >= 27 && (id-27)%31 == 0 {
			continue
		}
		out = append(out, id)
	}
	return out
}
