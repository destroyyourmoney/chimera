//go:build chimera_quic

package quic

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	utls "github.com/refraction-networking/utls"
)

const (
	extServerName                uint16 = 0
	extSupportedGroups           uint16 = 10
	extALPN                      uint16 = 16
	extSupportedVersions         uint16 = 43
	extKeyShare                  uint16 = 51
	extQUICTransportParameters   uint16 = 57
	handshakeTypeClientHello     byte   = 1
	legacyTLSHandshakeRecordType byte   = 0x16
)

type ClientHelloSummary struct {
	LegacyVersion   uint16
	CipherSuites    []uint16
	Extensions      []uint16
	SupportedGroups []uint16
	KeyShareGroups  []uint16
	SupportedVers   []uint16
	ALPN            []string
	SNI             string
	HasQUICParams   bool
	QUICParams      []uint64
}

type ClientHelloDiff struct {
	Field string
	Have  string
	Want  string
}

func BuildChromeH3ClientHelloReference(sni string) ([]byte, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, err
	}
	spec.TLSVersMin = utls.VersionTLS13
	spec.TLSVersMax = utls.VersionTLS13
	ensureChromeH3ReferenceExtensions(&spec)
	cfg := &utls.QUICConfig{
		TLSConfig: &utls.Config{
			ServerName: sni,
			NextProtos: []string{
				alpn,
			},
			MinVersion: utls.VersionTLS13,
			MaxVersion: utls.VersionTLS13,
		},
	}
	conn := utls.UQUICClient(cfg, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Start(ctx); err != nil {
		return nil, err
	}
	defer conn.Close()
	for {
		ev := conn.NextEvent()
		switch ev.Kind {
		case utls.QUICNoEvent:
			return nil, fmt.Errorf("utls reference: no Initial CRYPTO data")
		case utls.QUICWriteData:
			if ev.Level == utls.QUICEncryptionLevelInitial {
				return append([]byte(nil), ev.Data...), nil
			}
		}
	}
}

func ensureChromeH3ReferenceExtensions(spec *utls.ClientHelloSpec) {
	hasQUICParams := false
	for i, ext := range spec.Extensions {
		switch ext.(type) {
		case *utls.ALPNExtension:
			spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: []string{alpn}}
		case *utls.SupportedVersionsExtension:
			spec.Extensions[i] = &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}}
		case *utls.QUICTransportParametersExtension:
			hasQUICParams = true
		}
	}
	if !hasQUICParams {
		spec.Extensions = append(spec.Extensions, &utls.QUICTransportParametersExtension{
			TransportParameters: utls.TransportParameters{},
		})
	}
}

func SummarizeClientHello(data []byte) (ClientHelloSummary, error) {
	if len(data) >= 5 && data[0] == legacyTLSHandshakeRecordType {
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+recordLen {
			return ClientHelloSummary{}, fmt.Errorf("clienthello: truncated TLS record")
		}
		data = data[5 : 5+recordLen]
	}
	if len(data) < 4 || data[0] != handshakeTypeClientHello {
		return ClientHelloSummary{}, fmt.Errorf("clienthello: not a ClientHello handshake message")
	}
	helloLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+helloLen {
		return ClientHelloSummary{}, fmt.Errorf("clienthello: truncated handshake")
	}
	body := data[4 : 4+helloLen]
	var s ClientHelloSummary
	if len(body) < 34 {
		return s, fmt.Errorf("clienthello: truncated fixed header")
	}
	s.LegacyVersion = binary.BigEndian.Uint16(body[:2])
	pos := 34
	if pos >= len(body) {
		return s, fmt.Errorf("clienthello: missing session id")
	}
	sessionIDLen := int(body[pos])
	pos++
	if len(body) < pos+sessionIDLen+2 {
		return s, fmt.Errorf("clienthello: truncated session id")
	}
	pos += sessionIDLen
	suitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if suitesLen%2 != 0 || len(body) < pos+suitesLen+1 {
		return s, fmt.Errorf("clienthello: truncated cipher suites")
	}
	for end := pos + suitesLen; pos < end; pos += 2 {
		s.CipherSuites = append(s.CipherSuites, binary.BigEndian.Uint16(body[pos:pos+2]))
	}
	compLen := int(body[pos])
	pos++
	if len(body) < pos+compLen {
		return s, fmt.Errorf("clienthello: truncated compression methods")
	}
	pos += compLen
	if len(body) == pos {
		return s, nil
	}
	if len(body) < pos+2 {
		return s, fmt.Errorf("clienthello: truncated extension length")
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+extLen {
		return s, fmt.Errorf("clienthello: truncated extensions")
	}
	for end := pos + extLen; pos < end; {
		if end-pos < 4 {
			return s, fmt.Errorf("clienthello: truncated extension header")
		}
		typ := binary.BigEndian.Uint16(body[pos : pos+2])
		l := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if end-pos < l {
			return s, fmt.Errorf("clienthello: truncated extension %d", typ)
		}
		payload := body[pos : pos+l]
		pos += l
		s.Extensions = append(s.Extensions, typ)
		switch typ {
		case extServerName:
			s.SNI = parseSNI(payload)
		case extALPN:
			s.ALPN = parseALPN(payload)
		case extSupportedGroups:
			s.SupportedGroups = parseUint16Vector(payload)
		case extSupportedVersions:
			s.SupportedVers = parseSupportedVersions(payload)
		case extKeyShare:
			s.KeyShareGroups = parseKeyShareGroups(payload)
		case extQUICTransportParameters:
			s.HasQUICParams = true
			s.QUICParams = parseQUICTransportParameterIDs(payload)
		}
	}
	return s, nil
}

func DiffClientHelloSummaries(have, want ClientHelloSummary) []ClientHelloDiff {
	var diffs []ClientHelloDiff
	add := func(field string, a, b any) {
		diffs = append(diffs, ClientHelloDiff{Field: field, Have: fmt.Sprint(a), Want: fmt.Sprint(b)})
	}
	if have.LegacyVersion != want.LegacyVersion {
		add("legacy_version", fmt.Sprintf("0x%04x", have.LegacyVersion), fmt.Sprintf("0x%04x", want.LegacyVersion))
	}
	if !slices.Equal(normalizeGREASE16(have.CipherSuites), normalizeGREASE16(want.CipherSuites)) {
		add("cipher_suites", hex16s(normalizeGREASE16(have.CipherSuites)), hex16s(normalizeGREASE16(want.CipherSuites)))
	}
	if !equalGREASE16Multiset(have.Extensions, want.Extensions) {
		add("extensions", hex16s(normalizeGREASE16(have.Extensions)), hex16s(normalizeGREASE16(want.Extensions)))
	}
	if !slices.Equal(normalizeGREASE16(have.SupportedGroups), normalizeGREASE16(want.SupportedGroups)) {
		add("supported_groups", hex16s(normalizeGREASE16(have.SupportedGroups)), hex16s(normalizeGREASE16(want.SupportedGroups)))
	}
	if !slices.Equal(normalizeGREASE16(have.KeyShareGroups), normalizeGREASE16(want.KeyShareGroups)) {
		add("key_share_groups", hex16s(normalizeGREASE16(have.KeyShareGroups)), hex16s(normalizeGREASE16(want.KeyShareGroups)))
	}
	if !slices.Equal(normalizeGREASE16(have.SupportedVers), normalizeGREASE16(want.SupportedVers)) {
		add("supported_versions", hex16s(normalizeGREASE16(have.SupportedVers)), hex16s(normalizeGREASE16(want.SupportedVers)))
	}
	if !slices.Equal(have.ALPN, want.ALPN) {
		add("alpn", have.ALPN, want.ALPN)
	}
	if have.SNI != want.SNI {
		add("sni", have.SNI, want.SNI)
	}
	if have.HasQUICParams != want.HasQUICParams {
		add("quic_transport_parameters", have.HasQUICParams, want.HasQUICParams)
	}
	return diffs
}

func parseQUICTransportParameterIDs(b []byte) []uint64 {
	var ids []uint64
	for len(b) > 0 {
		id, n, err := quicvarint.Parse(b)
		if err != nil {
			return ids
		}
		b = b[n:]
		l, n, err := quicvarint.Parse(b)
		if err != nil || uint64(len(b[n:])) < l {
			return ids
		}
		b = b[n:]
		ids = append(ids, id)
		b = b[l:]
	}
	return ids
}

func parseSNI(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	pos := 2
	for end := min(len(b), 2+listLen); pos+3 <= end; {
		nameType := b[pos]
		l := int(binary.BigEndian.Uint16(b[pos+1 : pos+3]))
		pos += 3
		if pos+l > end {
			return ""
		}
		if nameType == 0 {
			return string(b[pos : pos+l])
		}
		pos += l
	}
	return ""
}

func parseALPN(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	pos := 2
	var out []string
	for end := min(len(b), 2+listLen); pos < end; {
		l := int(b[pos])
		pos++
		if pos+l > end {
			return out
		}
		out = append(out, string(b[pos:pos+l]))
		pos += l
	}
	return out
}

func parseUint16Vector(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	vecLen := int(binary.BigEndian.Uint16(b[:2]))
	pos := 2
	var out []uint16
	for end := min(len(b), 2+vecLen); pos+2 <= end; pos += 2 {
		out = append(out, binary.BigEndian.Uint16(b[pos:pos+2]))
	}
	return out
}

func parseSupportedVersions(b []byte) []uint16 {
	if len(b) < 1 {
		return nil
	}
	vecLen := int(b[0])
	pos := 1
	var out []uint16
	for end := min(len(b), 1+vecLen); pos+2 <= end; pos += 2 {
		out = append(out, binary.BigEndian.Uint16(b[pos:pos+2]))
	}
	return out
}

func parseKeyShareGroups(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	vecLen := int(binary.BigEndian.Uint16(b[:2]))
	pos := 2
	var out []uint16
	for end := min(len(b), 2+vecLen); pos+4 <= end; {
		group := binary.BigEndian.Uint16(b[pos : pos+2])
		l := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if pos+l > end {
			return out
		}
		out = append(out, group)
		pos += l
	}
	return out
}

func hex16s(v []uint16) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = fmt.Sprintf("0x%04x", x)
	}
	return out
}

func normalizeGREASE16(v []uint16) []uint16 {
	out := slices.Clone(v)
	for i, x := range out {
		if isGREASE16(x) {
			out[i] = 0x0a0a
		}
	}
	return out
}

func isGREASE16(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

func equalGREASE16Multiset(a, b []uint16) bool {
	aa := normalizeGREASE16(a)
	bb := normalizeGREASE16(b)
	slices.Sort(aa)
	slices.Sort(bb)
	return slices.Equal(aa, bb)
}
