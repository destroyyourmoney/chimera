//go:build chimera_quic

package quic

import (
	"encoding/binary"
	"fmt"
	"slices"

	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

type InitialPacketSummary struct {
	Packet          []byte
	Version         quicgo.Version
	DestConnIDLen   int
	SrcConnIDLen    int
	TokenLen        int
	PacketNumber    uint64
	PacketNumberLen int
	Length          int
	Frames          []string
}

type InitialPacketDiff struct {
	Field string
	Have  string
	Want  string
}

func SummarizeInitialPacketTrace(trace quicgo.InitialPacketTrace) InitialPacketSummary {
	return InitialPacketSummary{
		Packet:          append([]byte(nil), trace.Packet...),
		Version:         trace.Version,
		DestConnIDLen:   len(trace.DestConnectionID),
		SrcConnIDLen:    len(trace.SrcConnectionID),
		TokenLen:        len(trace.Token),
		PacketNumber:    trace.PacketNumber,
		PacketNumberLen: trace.PacketNumberLen,
		Length:          trace.Length,
		Frames:          append([]string(nil), trace.Frames...),
	}
}

func SummarizeInitialPacket(packet []byte) (InitialPacketSummary, error) {
	if len(packet) < 7 {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: truncated")
	}
	if packet[0]&0x80 == 0 {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: not a long header")
	}
	if packet[0]&0x30 != 0 {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: not an Initial packet")
	}
	pos := 1
	version := quicgo.Version(binary.BigEndian.Uint32(packet[pos : pos+4]))
	pos += 4
	dcidLen := int(packet[pos])
	pos++
	if len(packet) < pos+dcidLen+1 {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: truncated destination connection id")
	}
	pos += dcidLen
	scidLen := int(packet[pos])
	pos++
	if len(packet) < pos+scidLen {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: truncated source connection id")
	}
	pos += scidLen
	tokenLen, n, err := quicvarint.Parse(packet[pos:])
	if err != nil {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: token length: %w", err)
	}
	pos += n
	if uint64(len(packet[pos:])) < tokenLen {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: truncated token")
	}
	pos += int(tokenLen)
	length, _, err := quicvarint.Parse(packet[pos:])
	if err != nil {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: length: %w", err)
	}
	if uint64(len(packet[pos+n:])) < length {
		return InitialPacketSummary{}, fmt.Errorf("initial packet: truncated payload")
	}
	return InitialPacketSummary{
		Packet:        append([]byte(nil), packet...),
		Version:       version,
		DestConnIDLen: dcidLen,
		SrcConnIDLen:  scidLen,
		TokenLen:      int(tokenLen),
		Length:        len(packet),
	}, nil
}

func DiffInitialPacketSummaries(have, want InitialPacketSummary) []InitialPacketDiff {
	var diffs []InitialPacketDiff
	add := func(field string, a, b any) {
		diffs = append(diffs, InitialPacketDiff{Field: field, Have: fmt.Sprint(a), Want: fmt.Sprint(b)})
	}
	if have.Version != want.Version {
		add("version", have.Version, want.Version)
	}
	if have.Length != want.Length {
		add("length", have.Length, want.Length)
	}
	if have.DestConnIDLen != want.DestConnIDLen {
		add("dcid_len", have.DestConnIDLen, want.DestConnIDLen)
	}
	if have.SrcConnIDLen != want.SrcConnIDLen {
		add("scid_len", have.SrcConnIDLen, want.SrcConnIDLen)
	}
	if have.TokenLen != want.TokenLen {
		add("token_len", have.TokenLen, want.TokenLen)
	}
	if have.PacketNumberLen != want.PacketNumberLen {
		add("packet_number_len", have.PacketNumberLen, want.PacketNumberLen)
	}
	if !slices.Equal(have.Frames, want.Frames) {
		add("frames", have.Frames, want.Frames)
	}
	return diffs
}
