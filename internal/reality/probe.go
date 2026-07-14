//go:build chimera_utls

package reality

// Phase 1 of the ServerHello/JA3S-parity engine (ROADMAP Этап 1b,
// docs/reality-serverhello-engine.md, architecture A): probe the real
// steal-host with the same impersonated ClientHello CHIMERA's client sends,
// capture its genuine ServerHello, and parse it into a ServerHelloTemplate
// that a later serving engine (Phase 2) can replay the observable shape of.
//
// This file only probes and parses; it is not yet wired into ServerWrap.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

const (
	recordTypeHandshake      = 0x16
	recordTypeAlert          = 0x15
	handshakeTypeServerHello = 0x02

	// extensionSupportedVersionsType and extensionKeyShare are the only two
	// extensions a fresh TLS 1.3 ServerHello carries in this codebase; their
	// relative wire order is part of the JA3S fingerprint (see ServerWrap's
	// use of extensionOrderFromTemplate and third_party/utls's ServerHelloShape).
	extensionSupportedVersionsType = 0x002b
	extensionKeyShare              = 0x0033

	probeWriteTimeout = 5 * time.Second
	probeReadTimeout  = 8 * time.Second

	maxRecordLen = 16384 + 256 // generous slack over the 2^14 plaintext limit
)

var errNotServerHello = errors.New("reality: probe: first handshake message is not a ServerHello")

// errHelloRetryRequest is returned by ParseServerHello when the message is a
// HelloRetryRequest rather than a genuine ServerHello (RFC 8446 §4.1.4): the
// server didn't like any key_share our probe's ClientHello offered and asked
// for a different one. Wire-wise an HRR is a ServerHello with the same
// handshake_type=2, distinguished only by a magic Random value -- its
// key_share extension (if present) is just a bare 2-byte selected_group, not
// a public key, so treating it as a normal ServerHello would poison the
// template cache with a KeyShareGroup that looks valid but isn't paired with
// a real key exchange. A real CDN can send this on a probe whose pinned
// ClientHello didn't happen to guess its preferred group first -- the local
// crypto/tls stand-in used elsewhere in this package's tests never triggers
// it (its group always matches), so this path only exercises against real
// external hosts (docs/reality-serverhello-engine.md "Not yet done" gap).
var errHelloRetryRequest = errors.New("reality: probe: server sent HelloRetryRequest, not a ServerHello")

// helloRetryRequestRandom is the fixed Random value RFC 8446 §4.1.3 mandates
// for a HelloRetryRequest: SHA-256("HelloRetryRequest").
var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// ExtensionRecord is one TLS extension as observed on the wire: its type and
// raw (still-encoded) content. Order in a ServerHelloTemplate.Extensions
// slice is the wire order, which is itself part of the fingerprint.
type ExtensionRecord struct {
	Type uint16
	Data []byte
}

// ServerHelloTemplate captures the observable shape of a genuine ServerHello
// from a real steal-host: everything a passive JA3S fingerprint keys on.
//
// It deliberately does NOT capture anything CHIMERA must not literally
// replay: Random must be fresh per session, and the key_share extension's
// public key is the steal-host's own (secret to it) -- CHIMERA substitutes
// its own key_share public key when serving, keeping only KeyShareGroup (the
// negotiated group id) so the substituted key stays shape-consistent.
type ServerHelloTemplate struct {
	LegacyVersion     uint16
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        []ExtensionRecord // wire order, as observed
	KeyShareGroup     uint16            // 0 if the key_share extension was absent
	CapturedAt        time.Time
}

// ProbeServerHello dials dest via dial, sends a ClientHello matching the
// impersonated Fingerprint, reads and parses the server's raw ServerHello,
// then closes the connection -- the rest of the (encrypted) handshake is
// irrelevant to JA3S and is never started.
func ProbeServerHello(dial func() (net.Conn, error), sni string) (*ServerHelloTemplate, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("reality: probe: dial: %w", err)
	}
	defer conn.Close()

	hello, err := buildProbeClientHello(sni)
	if err != nil {
		return nil, err
	}

	_ = conn.SetWriteDeadline(time.Now().Add(probeWriteTimeout))
	if err := writeHandshakeRecord(conn, hello); err != nil {
		return nil, fmt.Errorf("reality: probe: write client hello: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(probeReadTimeout))
	raw, err := readServerHelloMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("reality: probe: read server hello: %w", err)
	}
	return ParseServerHello(raw)
}

// buildProbeClientHello marshals a ClientHello for the pinned Fingerprint
// (the same impersonation the authorized client path uses) without
// performing any I/O -- BuildHandshakeState/MarshalClientHello are pure
// construction, matching how ClientWrap builds its own ClientHello.
func buildProbeClientHello(sni string) ([]byte, error) {
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
	}
	pr, pw := net.Pipe()
	defer pr.Close()
	defer pw.Close()

	u := utls.UClient(pr, cfg, Fingerprint)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: probe: build hello: %w", err)
	}
	if err := u.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("reality: probe: marshal hello: %w", err)
	}
	raw := u.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		return nil, errors.New("reality: probe: empty client hello")
	}
	return append([]byte(nil), raw...), nil
}

// writeHandshakeRecord wraps a handshake message (already including its
// 4-byte type+length header) in one or more TLS records.
func writeHandshakeRecord(w io.Writer, msg []byte) error {
	for len(msg) > 0 {
		n := len(msg)
		if n > 16384 {
			n = 16384
		}
		var hdr [5]byte
		hdr[0] = recordTypeHandshake
		binary.BigEndian.PutUint16(hdr[1:3], 0x0301) // record-layer version: legacy, per RFC 8446 §5.1
		binary.BigEndian.PutUint16(hdr[3:5], uint16(n))
		if _, err := w.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := w.Write(msg[:n]); err != nil {
			return err
		}
		msg = msg[n:]
	}
	return nil
}

// readServerHelloMessage reads TLS records until the first handshake message
// (which must be a ServerHello) is fully assembled, and returns its bytes
// including the 4-byte handshake header.
func readServerHelloMessage(r io.Reader) ([]byte, error) {
	var buf []byte
	haveLen := false
	need := 4
	for {
		typ, data, err := readTLSRecord(r)
		if err != nil {
			return nil, err
		}
		switch typ {
		case recordTypeAlert:
			return nil, fmt.Errorf("reality: probe: received TLS alert: %x", data)
		case recordTypeHandshake:
			buf = append(buf, data...)
		default:
			continue // change_cipher_spec compat records etc: not the message we want
		}
		if !haveLen && len(buf) >= 4 {
			if buf[0] != handshakeTypeServerHello {
				return nil, errNotServerHello
			}
			bodyLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
			need = 4 + bodyLen
			haveLen = true
		}
		if haveLen && len(buf) >= need {
			return buf[:need], nil
		}
	}
}

func readTLSRecord(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > maxRecordLen {
		return 0, nil, fmt.Errorf("reality: probe: implausible record length %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	return hdr[0], data, nil
}

// ParseServerHello parses a ServerHello handshake message (including its
// 4-byte type+length header, as returned by readServerHelloMessage) into a
// ServerHelloTemplate.
func ParseServerHello(raw []byte) (*ServerHelloTemplate, error) {
	if len(raw) < 4 {
		return nil, errors.New("reality: parse server hello: message too short")
	}
	if raw[0] != handshakeTypeServerHello {
		return nil, errNotServerHello
	}
	bodyLen := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if len(raw) < 4+bodyLen {
		return nil, errors.New("reality: parse server hello: truncated body")
	}
	s := cryptobyte.String(raw[4 : 4+bodyLen])

	tmpl := &ServerHelloTemplate{CapturedAt: time.Now()}

	if !s.ReadUint16(&tmpl.LegacyVersion) {
		return nil, errors.New("reality: parse server hello: legacy_version")
	}
	var random [32]byte
	if !s.CopyBytes(random[:]) {
		return nil, errors.New("reality: parse server hello: random")
	}
	if random == helloRetryRequestRandom {
		return nil, errHelloRetryRequest
	}
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("reality: parse server hello: legacy_session_id_echo")
	}
	if !s.ReadUint16(&tmpl.CipherSuite) {
		return nil, errors.New("reality: parse server hello: cipher_suite")
	}
	if !s.ReadUint8(&tmpl.CompressionMethod) {
		return nil, errors.New("reality: parse server hello: legacy_compression_method")
	}

	if s.Empty() {
		return tmpl, nil // no extensions block: unusual for TLS 1.3 but not our concern to reject here
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("reality: parse server hello: extensions")
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("reality: parse server hello: malformed extension")
		}
		data := append([]byte(nil), extData...)
		tmpl.Extensions = append(tmpl.Extensions, ExtensionRecord{Type: extType, Data: data})
		if extType == extensionKeyShare && len(data) >= 2 {
			tmpl.KeyShareGroup = binary.BigEndian.Uint16(data[:2])
		}
	}
	return tmpl, nil
}

// --- per-host template cache ---

const defaultTemplateTTL = 10 * time.Minute

type templateCacheEntry struct {
	tmpl *ServerHelloTemplate
	err  error
	at   time.Time
}

type templateCache struct {
	mu  sync.Mutex
	m   map[string]templateCacheEntry
	ttl time.Duration
}

var probeCache = &templateCache{m: map[string]templateCacheEntry{}, ttl: defaultTemplateTTL}

// ServerHelloTemplateFor returns a cached ServerHelloTemplate for sni,
// probing dest (via dial) when the cache is empty or stale. dial should open
// a fresh TCP connection to the steal-host on every call (e.g. wrapping
// preconnect.Pool.Get or net.Dial); callers typically pass steal-host's SNI
// as sni.
//
// A probe failure is cached too (briefly, same TTL), so a momentarily
// unreachable steal-host doesn't cause a probe storm; callers should treat a
// non-nil error as "no template available" and fall back to the current
// stock ServerHello rather than failing the session.
func ServerHelloTemplateFor(dial func() (net.Conn, error), sni string) (*ServerHelloTemplate, error) {
	return probeCache.get(sni, dial)
}

func (c *templateCache) get(key string, dial func() (net.Conn, error)) (*ServerHelloTemplate, error) {
	c.mu.Lock()
	if e, ok := c.m[key]; ok && time.Since(e.at) < c.ttl {
		c.mu.Unlock()
		return e.tmpl, e.err
	}
	c.mu.Unlock()

	tmpl, err := ProbeServerHello(dial, key)

	c.mu.Lock()
	c.m[key] = templateCacheEntry{tmpl: tmpl, err: err, at: time.Now()}
	c.mu.Unlock()
	return tmpl, err
}

// reset drops every cached template, forcing the next ServerHelloTemplateFor
// call for each host to re-probe.
func (c *templateCache) reset() {
	c.mu.Lock()
	c.m = map[string]templateCacheEntry{}
	c.mu.Unlock()
}

// InvalidateServerHelloTemplates drops every cached ServerHelloTemplate, so
// the next authorized session re-probes its steal-host. SetFingerprint calls
// this automatically (a cached template was captured with the *previous*
// impersonated ClientHello, and a different Chrome build can genuinely
// change what a real peer negotiates -- e.g. cipher suite order or PQ
// group support -- so a stale template could force a shape the real
// steal-host would no longer produce for the new ClientHello). Exposed so
// the same invalidation can be triggered by anything else that changes probe
// inputs (ROADMAP Этап 5 fingerprint pipeline, docs/reality-serverhello-engine.md Phase 4).
func InvalidateServerHelloTemplates() {
	probeCache.reset()
}
