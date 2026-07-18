//go:build chimera_utls

package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"chimera/internal/auth"
)

const (
	confirmLabel   = "chimera-reality-confirm-v0"
	confirmLen     = 32
	confirmTimeout = 10 * time.Second
)

var (
	errNoEcdhe     = errors.New("reality: uTLS produced no X25519 ephemeral")
	errConfirmFail = errors.New("reality: PSK confirmation failed (peer does not know the shared secret)")
)

var Fingerprint = utls.HelloChrome_133

var fingerprintByName = map[string]utls.ClientHelloID{
	"chrome":    utls.HelloChrome_133,
	"chrome131": utls.HelloChrome_131,
	"chrome120": utls.HelloChrome_120,
	"firefox":   utls.HelloFirefox_120,
	"safari":    utls.HelloSafari_16_0,
	"ios":       utls.HelloIOS_14,
	"edge":      utls.HelloEdge_85,
}

func SetFingerprint(name string) error {
	id, ok := fingerprintByName[name]
	if !ok {
		return fmt.Errorf("reality: unknown fingerprint %q", name)
	}
	Fingerprint = id
	InvalidateServerHelloTemplates()
	return nil
}

func ClientWrap(conn net.Conn, serverPub *ecdh.PublicKey, sni, shortIDHex string) (net.Conn, []byte, error) {
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
	}
	u := utls.UClient(conn, cfg, Fingerprint)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, nil, fmt.Errorf("reality: build hello: %w", err)
	}

	ks := u.HandshakeState.State13.KeyShareKeys
	if ks == nil || ks.Ecdhe == nil {
		return nil, nil, errNoEcdhe
	}
	eph := ks.Ecdhe

	ss, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("reality: ecdh: %w", err)
	}
	tag, err := auth.Seal(ss, eph.PublicKey().Bytes(), serverPub.Bytes(), parseShortID(shortIDHex))
	if err != nil {
		return nil, nil, fmt.Errorf("reality: seal auth tag: %w", err)
	}
	u.HandshakeState.Hello.SessionId = padTo32(tag)
	if err := u.MarshalClientHello(); err != nil {
		return nil, nil, fmt.Errorf("reality: marshal hello: %w", err)
	}
	if err := u.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("reality: tls handshake: %w", err)
	}

	if err := confirm(u, ss, true); err != nil {
		return nil, nil, err
	}
	return u, ss, nil
}

func ServerWrap(conn net.Conn, prefix, ss []byte, stealHostAddr string) (net.Conn, error) {
	certHost := stealHostname(stealHostAddr)
	cert, err := certFor(certHost)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{
		Certificates: []utls.Certificate{cert},
		MinVersion:   utls.VersionTLS13,
		MaxVersion:   utls.VersionTLS13,

		CurvePreferences: []utls.CurveID{utls.X25519, utls.X25519MLKEM768},
		ServerHelloShape: serverHelloShapeFor(stealHostAddr, certHost),
	}
	pc := &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
	tc := utls.Server(pc, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("reality: server handshake: %w", err)
	}

	if err := confirm(tc, ss, false); err != nil {
		return nil, err
	}
	return tc, nil
}

func stealHostname(stealHostAddr string) string {
	if h, _, err := net.SplitHostPort(stealHostAddr); err == nil {
		return h
	}
	return stealHostAddr
}

func serverHelloShapeFor(stealHostAddr, sni string) *utls.ServerHelloShape {
	dial := func() (net.Conn, error) { return net.Dial("tcp", stealHostAddr) }
	tmpl, err := ServerHelloTemplateFor(dial, sni)
	if err != nil {
		slog.Debug("reality: no ServerHello template, using stock ordering", "steal_host", stealHostAddr, "err", err)
		return nil
	}
	return &utls.ServerHelloShape{
		ForceCipherSuite: tmpl.CipherSuite,
		ForceGroup:       utls.CurveID(tmpl.KeyShareGroup),
		ExtensionOrder:   extensionOrderFromTemplate(tmpl),
	}
}

func extensionOrderFromTemplate(tmpl *ServerHelloTemplate) []uint16 {
	var order []uint16
	for _, e := range tmpl.Extensions {
		if e.Type == extensionSupportedVersionsType || e.Type == extensionKeyShare {
			order = append(order, e.Type)
		}
	}
	return order
}

func confirm(rw io.ReadWriter, ss []byte, isClient bool) error {
	if c, ok := rw.(net.Conn); ok {
		_ = c.SetDeadline(time.Now().Add(confirmTimeout))
		defer c.SetDeadline(time.Time{})
	}
	mine := proof(ss, role(isClient))
	theirs := proof(ss, role(!isClient))

	send := func() error { _, err := rw.Write(mine); return err }
	recv := func() error {
		got := make([]byte, confirmLen)
		if _, err := io.ReadFull(rw, got); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(got, theirs) != 1 {
			return errConfirmFail
		}
		return nil
	}

	if isClient {
		if err := send(); err != nil {
			return err
		}
		return recv()
	}
	if err := recv(); err != nil {
		return err
	}
	return send()
}

func role(client bool) string {
	if client {
		return "client"
	}
	return "server"
}

func proof(ss []byte, tag string) []byte {
	m := hmac.New(sha256.New, ss)
	m.Write([]byte(confirmLabel))
	m.Write([]byte(tag))
	return m.Sum(nil)
}

func parseShortID(s string) []byte {
	out := make([]byte, auth.ShortIDLen)
	if b, err := hex.DecodeString(s); err == nil {
		copy(out, b)
	}
	return out
}

func padTo32(tag []byte) []byte {
	sid := make([]byte, 32)
	copy(sid, tag)
	if len(tag) < 32 {
		_, _ = rand.Read(sid[len(tag):])
	}
	return sid
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

var (
	certMu    sync.Mutex
	certCache = map[string]utls.Certificate{}
)

func certFor(host string) (utls.Certificate, error) {
	certMu.Lock()
	defer certMu.Unlock()
	if c, ok := certCache[host]; ok {
		return c, nil
	}
	c, err := selfSigned(host)
	if err != nil {
		return utls.Certificate{}, err
	}
	certCache[host] = c
	return c, nil
}

func selfSigned(host string) (utls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return utls.Certificate{}, fmt.Errorf("reality: gen cert key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return utls.Certificate{}, fmt.Errorf("reality: gen serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return utls.Certificate{}, fmt.Errorf("reality: create cert: %w", err)
	}
	return utls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
