// Package clienthello builds a minimal TLS 1.3 ClientHello on the client side
// (carrying the CHIMERA auth tag in the SessionID and the ephemeral X25519 key
// in key_share) and defensively parses an untrusted ClientHello on the server
// side to recover those two fields.
//
// NOTE: this hand-rolled ClientHello does NOT yet reproduce a real browser
// fingerprint. Fingerprint parity (JA3/JA4 == Chrome) is Phase 1b and requires
// swapping the client builder for uTLS. The parser, however, is the real
// server-side primitive and stays.
package clienthello

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const x25519Group = 0x001d

var (
	errShort          = errors.New("clienthello: short buffer")
	errNotHandshake   = errors.New("clienthello: not a TLS handshake record")
	errNotClientHello = errors.New("clienthello: not a ClientHello")
)

// ---------- builder ----------

func u16(n int) []byte      { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(n)); return b }
func u24(n int) []byte      { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
func pfx16(b []byte) []byte { return append(u16(len(b)), b...) }

func ext(typ int, data []byte) []byte {
	return append(u16(typ), pfx16(data)...)
}

// Build constructs a TLS 1.3 ClientHello record. sessionID carries the auth tag
// (padded to 32 bytes); x25519Pub is the client's ephemeral key_share.
func Build(sni string, sessionID, x25519Pub []byte) []byte {
	random := make([]byte, 32)
	_, _ = rand.Read(random)

	sid := make([]byte, 32) // pad to a realistic 32-byte session id
	copy(sid, sessionID)
	if len(sessionID) < 32 {
		_, _ = rand.Read(sid[len(sessionID):])
	}

	cipherSuites := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03} // AES128/256-GCM, ChaCha20

	// extensions
	var exts []byte
	// server_name
	name := []byte(sni)
	sniEntry := append(append([]byte{0x00}, u16(len(name))...), name...)
	exts = append(exts, ext(0x0000, pfx16(sniEntry))...)
	// supported_groups: x25519
	exts = append(exts, ext(0x000a, pfx16([]byte{0x00, 0x1d}))...)
	// supported_versions: TLS 1.3
	exts = append(exts, append(u16(0x002b), pfx16([]byte{0x02, 0x03, 0x04})...)...)
	// signature_algorithms
	sigs := []byte{0x04, 0x03, 0x08, 0x04, 0x08, 0x07} // ecdsa_p256, rsa_pss_sha256, ed25519
	exts = append(exts, ext(0x000d, pfx16(sigs))...)
	// key_share: x25519 entry
	ksEntry := append(append([]byte{0x00, 0x1d}, u16(len(x25519Pub))...), x25519Pub...)
	exts = append(exts, ext(0x0033, pfx16(ksEntry))...)

	// ClientHello body
	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version
	body = append(body, random...)
	body = append(body, byte(len(sid)))
	body = append(body, sid...)
	body = append(body, pfx16(cipherSuites)...)
	body = append(body, 0x01, 0x00) // compression: 1 method, null
	body = append(body, pfx16(exts)...)

	// handshake
	hs := append(append([]byte{0x01}, u24(len(body))...), body...)

	// record
	rec := append(append([]byte{0x16, 0x03, 0x01}, u16(len(hs))...), hs...)
	return rec
}

// ---------- defensive parser (server side) ----------

type cur struct {
	b []byte
	e error
}

func (c *cur) need(n int) []byte {
	if c.e != nil {
		return nil
	}
	if n < 0 || len(c.b) < n {
		c.e = errShort
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}
func (c *cur) u8() int {
	v := c.need(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}
func (c *cur) u16() int {
	v := c.need(2)
	if v == nil {
		return 0
	}
	return int(v[0])<<8 | int(v[1])
}
func (c *cur) u24() int {
	v := c.need(3)
	if v == nil {
		return 0
	}
	return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
}

// Parse extracts the SessionID and the X25519 key_share from a ClientHello.
func Parse(raw []byte) (sessionID, x25519Pub []byte, err error) {
	c := &cur{b: raw}
	if c.u8() != 0x16 {
		return nil, nil, errNotHandshake
	}
	c.need(2) // record version
	rec := c.need(c.u16())
	if c.e != nil {
		return nil, nil, c.e
	}

	h := &cur{b: rec}
	if h.u8() != 0x01 {
		return nil, nil, errNotClientHello
	}
	body := h.need(h.u24())
	if h.e != nil {
		return nil, nil, h.e
	}

	p := &cur{b: body}
	p.need(2)  // legacy_version
	p.need(32) // random
	sessionID = p.need(p.u8())
	p.need(p.u16()) // cipher_suites
	p.need(p.u8())  // compression_methods
	exts := p.need(p.u16())
	if p.e != nil {
		return nil, nil, p.e
	}

	e := &cur{b: exts}
	for len(e.b) >= 4 && e.e == nil {
		typ := e.u16()
		data := e.need(e.u16())
		if e.e != nil {
			break
		}
		if typ == 0x0033 {
			x25519Pub = parseKeyShare(data)
		}
	}
	return sessionID, x25519Pub, nil
}

func parseKeyShare(data []byte) []byte {
	k := &cur{b: data}
	list := k.need(k.u16())
	if k.e != nil {
		return nil
	}
	e := &cur{b: list}
	for len(e.b) >= 4 && e.e == nil {
		group := e.u16()
		key := e.need(e.u16())
		if e.e != nil {
			break
		}
		if group == x25519Group {
			return key
		}
	}
	return nil
}

// ---------- pluggable builder (Phase 1b integration seam) ----------

// Builder produces the ClientHello for the carrier handshake. StdlibBuilder is
// the PoC builder; the uTLS builder (build tag chimera_utls) reproduces a real
// Chrome fingerprint without changing any caller.
type Builder interface {
	BuildClientHello(sni string, sessionID, x25519Pub []byte) []byte
}

// StdlibBuilder wraps the hand-rolled Build.
type StdlibBuilder struct{}

// BuildClientHello implements Builder.
func (StdlibBuilder) BuildClientHello(sni string, sessionID, x25519Pub []byte) []byte {
	return Build(sni, sessionID, x25519Pub)
}

// Active is the builder used by the carrier; the uTLS build tag swaps it.
var Active Builder = StdlibBuilder{}
