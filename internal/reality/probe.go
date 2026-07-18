//go:build chimera_utls

package reality

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

	extensionSupportedVersionsType = 0x002b
	extensionKeyShare              = 0x0033

	probeWriteTimeout = 5 * time.Second
	probeReadTimeout  = 8 * time.Second

	maxRecordLen = 16384 + 256
)

var errNotServerHello = errors.New("reality: probe: first handshake message is not a ServerHello")

var errHelloRetryRequest = errors.New("reality: probe: server sent HelloRetryRequest, not a ServerHello")

var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

type ExtensionRecord struct {
	Type uint16
	Data []byte
}

type ServerHelloTemplate struct {
	LegacyVersion     uint16
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        []ExtensionRecord
	KeyShareGroup     uint16
	CapturedAt        time.Time
}

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

func writeHandshakeRecord(w io.Writer, msg []byte) error {
	for len(msg) > 0 {
		n := len(msg)
		if n > 16384 {
			n = 16384
		}
		var hdr [5]byte
		hdr[0] = recordTypeHandshake
		binary.BigEndian.PutUint16(hdr[1:3], 0x0301)
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
			continue
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
		return tmpl, nil
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

func (c *templateCache) reset() {
	c.mu.Lock()
	c.m = map[string]templateCacheEntry{}
	c.mu.Unlock()
}

func InvalidateServerHelloTemplates() {
	probeCache.reset()
}
