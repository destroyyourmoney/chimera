//go:build chimera_utls

// Package reality implements the CHIMERA authorized-session handshake takeover
// (Этап 1b). It is compiled in only under the `chimera_utls` build tag.
//
// For an authorized client the session becomes a REAL TLS 1.3 handshake rather
// than a cleartext inner stream:
//
//   - Client (ClientWrap): runs a live uTLS Chrome handshake. uTLS generates the
//     X25519 ephemeral; we read it back and reuse it as the CHIMERA auth key
//     (ss = X25519(eph, server_static_pub)) — so the key_share stays internally
//     consistent and the handshake completes for real. The auth tag rides in the
//     SessionId, exactly as before.
//   - Server (ServerWrap): the carrier has already gated on the auth tag and
//     recomputed ss. It now terminates a real TLS 1.3 session with crypto/tls,
//     presenting a self-signed certificate for the steal-host name. Because TLS
//     1.3 encrypts everything after ServerHello, a passive observer cannot tell
//     the certificate is self-signed rather than the real steal-host's.
//
// PKI is intentionally bypassed (InsecureSkipVerify): the client authenticates
// the server via a PSK proof keyed by ss and bound to the TLS session via the
// RFC 8446 exporter. A peer that does not know ss (the real steal-host, or any
// MITM) cannot produce the proof, so the client refuses to tunnel through it.
// A prober without a valid auth tag never reaches this code — it is spliced to
// the steal-host upstream, wire-identical to a normal visitor.
//
// Honest PoC scope vs full VLESS-Reality: the ServerHello is crypto/tls's (not
// relayed from the steal-host) and the certificate is self-signed (not the
// steal-host's real chain). Both are hidden from passive DPI by TLS 1.3 record
// encryption; relaying the steal-host's genuine ServerHello/Certificate is a
// later refinement.
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

// Fingerprint is the impersonated browser ClientHello. It is PINNED (not
// HelloChrome_Auto) so the JA3/JA4 we present is deterministic and does not
// silently drift with the uTLS version — keep it in sync with the Chrome stable
// you actually want to look like (ROADMAP Этап 5: fingerprint update pipeline).
var Fingerprint = utls.HelloChrome_133

// fingerprintByName maps operator-facing names to pinned uTLS ClientHelloIDs.
var fingerprintByName = map[string]utls.ClientHelloID{
	"chrome":    utls.HelloChrome_133,
	"chrome131": utls.HelloChrome_131,
	"chrome120": utls.HelloChrome_120,
	"firefox":   utls.HelloFirefox_120,
	"safari":    utls.HelloSafari_16_0,
	"ios":       utls.HelloIOS_14,
	"edge":      utls.HelloEdge_85,
}

// SetFingerprint pins the impersonated browser by name. Unknown names are an
// error. Also invalidates every cached ServerHelloTemplate (Этап 5
// fingerprint pipeline / docs/reality-serverhello-engine.md Phase 4): a
// template probed with the previous ClientHello may no longer reflect what
// a real steal-host negotiates against the new one.
func SetFingerprint(name string) error {
	id, ok := fingerprintByName[name]
	if !ok {
		return fmt.Errorf("reality: unknown fingerprint %q", name)
	}
	Fingerprint = id
	InvalidateServerHelloTemplates()
	return nil
}

// ClientWrap performs the authorized client handshake over conn and returns the
// established TLS connection plus the shared secret ss (for seeded padding).
func ClientWrap(conn net.Conn, serverPub *ecdh.PublicKey, sni, shortIDHex string) (net.Conn, []byte, error) {
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // authentication is via ss, not PKI
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

// ServerWrap terminates the authorized TLS session. prefix is the already-read
// ClientHello (plus any buffered bytes) that must be re-fed to the TLS stack;
// ss is the secret the carrier recovered during the auth gate; stealHostAddr
// is the steal-host's dial address (host:port) -- its hostname is used both
// as the self-signed certificate's CN/SAN and as the SNI for the ServerHello
// template probe (ROADMAP Этап 1b, docs/reality-serverhello-engine.md).
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
		// Both groups the impersonated Chrome ClientHello offers are allowed
		// here, so ForceGroup (below) can steer the TLS-level negotiation
		// toward whichever one a real steal-host's template calls for. This
		// is safe for the ss-based auth: ss is derived by the auth gate
		// (clienthello.Parse/auth.Open, before ServerWrap ever runs) from
		// the plain X25519 key_share entry specifically -- uTLS's
		// KeySharePrivateKeys keeps a SEPARATE ecdh key (MlkemEcdhe) for the
		// X25519MLKEM768 entry's classical component, so which group the
		// live TLS handshake actually negotiates never touches ss. See
		// docs/reality-serverhello-engine.md Phase 4 note.
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

// stealHostname strips the port from a host:port dial address for use as a
// certificate CN/SAN and SNI.
func stealHostname(stealHostAddr string) string {
	if h, _, err := net.SplitHostPort(stealHostAddr); err == nil {
		return h
	}
	return stealHostAddr
}

// serverHelloShapeFor returns a ServerHelloShape built from a cached (or
// freshly probed) ServerHelloTemplate for stealHostAddr, or nil if none is
// available (e.g. the steal-host is momentarily unreachable) -- a nil shape
// leaves the TLS stack's normal negotiation/serialization order untouched,
// which is no worse than CHIMERA's behavior before this engine existed.
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

// extensionOrderFromTemplate extracts the relative order of the
// supported_versions/key_share extensions from a captured template. Any
// other extension type present in the template is irrelevant here: CHIMERA's
// own ServerHello marshaler only knows how to order these two (see
// third_party/utls handshake_messages.go); a template that doesn't reduce to
// exactly these two, in some order, yields an order the marshaler will
// reject at emit time and fall back to its own default for.
func extensionOrderFromTemplate(tmpl *ServerHelloTemplate) []uint16 {
	var order []uint16
	for _, e := range tmpl.Extensions {
		if e.Type == extensionSupportedVersionsType || e.Type == extensionKeyShare {
			order = append(order, e.Type)
		}
	}
	return order
}

// confirm runs the mutual PSK proof. Because ss is derived from the TLS
// handshake's own X25519 ephemeral, only the two legitimate endpoints of THIS
// session share it, so the proof is inherently session-bound. The client writes
// first, then reads; the server reads first, then writes.
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

// --- helpers ---

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

// prefixConn re-delivers already-consumed bytes (the peeked ClientHello) before
// reading the rest of the live connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// --- self-signed certificate cache (one per host) ---

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
