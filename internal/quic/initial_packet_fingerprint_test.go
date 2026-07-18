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

func assertTransportParameterOrder(t *testing.T, ids []uint64) {
	t.Helper()
	ids = stripGREASETransportParameterIDs(ids)
	present := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		present[id] = true
	}
	required := []uint64{
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x01,
		0x03,
		0x0f,
		0x20,
		0x11,
		0x3127,
		0x3128,
	}
	for _, want := range required {
		if !present[want] {
			t.Fatalf("transport parameter set %x is missing required id 0x%x", ids, want)
		}
	}
	forbidden := []uint64{
		0x0a,
		0x0b,
		0x0c,
		0x0e,
		0x17f7586d2cb571,
		0xff04de1b,
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
