//go:build chimera_ss

// Shadowsocks-AEAD carrier (ROADMAP2 §3): a 4th anti-censorship strategy,
// deliberately NOT modeled on Reality/QUIC's "look like a real protocol"
// approach. There is no TLS ClientHello, no QUIC framing -- the wire is an
// ephemeral X25519 public key followed by a stream of AEAD-sealed chunks
// that, to an observer, looks like arbitrary encrypted noise rather than
// any known protocol. Positioning (see anticensorship_page.dart): minimal
// overhead / highest throughput, at the cost of not being disguised as
// anything specific.
//
// Honest compromise, documented rather than glossed over: unlike the TCP
// carrier's steal-host splice (server.spliceConn) or Reality's TLS
// takeover, an unauthenticated peer here gets no camouflage traffic at
// all -- a failed handshake or auth check just closes the connection. An
// active prober can therefore distinguish "something is listening but
// doesn't respond like a known protocol" from a real closed port, which
// Reality/QUIC specifically avoid. This is the class of tradeoff ROADMAP2
// §0.1 п.3 asks to document rather than paper over.
package carrier

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"chimera/internal/keys"
	"chimera/internal/ratelimit"
	"chimera/internal/tunnel"
)

func init() {
	SSDialConnect = ssDialConnect
	SSPing = ssPing
	SSServe = ssServe
}

const (
	ssWindowSeconds = 120 // matches internal/auth's anti-replay window
	ssShortIDLen    = 4   // matches auth.ShortIDLen
	ssMaxChunk      = 0x3FFF
)

// --- minimal HKDF-SHA256 (RFC 5869), duplicated from internal/auth rather
// than imported, since it's a 15-line primitive and this file intentionally
// stays decoupled from the TLS-handshake-specific auth package: the
// Shadowsocks framing has nothing analogous to a ClientHello SessionID to
// share code around. ---

func ssHkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func ssHkdfExpand(prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func ssDeriveKey(ss, salt []byte, info string) []byte {
	prk := ssHkdfExtract(salt, ss)
	return ssHkdfExpand(prk, []byte(info), 32)
}

// ssKeys holds the two direction-specific AEAD keys derived from one ECDH
// shared secret -- separate keys per direction (rather than one key with a
// disjoint nonce space) so nonce-uniqueness never depends on careful
// counter-offset bookkeeping between directions.
type ssKeys struct {
	c2s cipher.AEAD // client -> server
	s2c cipher.AEAD // server -> client
}

func newSSKeys(ss, serverPub []byte) (ssKeys, error) {
	c2sKey := ssDeriveKey(ss, serverPub, "chimera-ss-v0-c2s")
	s2cKey := ssDeriveKey(ss, serverPub, "chimera-ss-v0-s2c")
	c2s, err := ssNewGCM(c2sKey)
	if err != nil {
		return ssKeys{}, err
	}
	s2c, err := ssNewGCM(s2cKey)
	if err != nil {
		return ssKeys{}, err
	}
	return ssKeys{c2s: c2s, s2c: s2c}, nil
}

func ssNewGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ssConn wraps a raw net.Conn with the AEAD-chunked framing: each chunk is
// [AEAD-sealed 2-byte length][AEAD-sealed payload], nonces are a
// monotonically incrementing 12-byte counter per direction (two AEAD
// operations, hence two nonces, per chunk). This becomes the transport
// tunnel.Session's own padded control-frame protocol rides on top of,
// unchanged -- exactly like the plain-TCP and Reality-TLS builds.
type ssConn struct {
	net.Conn
	sendAEAD, recvAEAD   cipher.AEAD
	sendCounter          uint64
	recvCounter          uint64
	recvBuf              []byte // leftover decrypted payload not yet consumed by Read
}

func newSSConn(c net.Conn, sendAEAD, recvAEAD cipher.AEAD) *ssConn {
	return &ssConn{Conn: c, sendAEAD: sendAEAD, recvAEAD: recvAEAD}
}

func (s *ssConn) nonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func (s *ssConn) seal(aead cipher.AEAD, counter *uint64, plaintext []byte) []byte {
	out := aead.Seal(nil, s.nonce(*counter), plaintext, nil)
	*counter++
	return out
}

func (s *ssConn) open(aead cipher.AEAD, counter *uint64, sealed []byte) ([]byte, error) {
	out, err := aead.Open(nil, s.nonce(*counter), sealed, nil)
	if err != nil {
		return nil, err
	}
	*counter++
	return out, nil
}

// writeChunk sends one length-then-payload chunk pair.
func (s *ssConn) writeChunk(payload []byte) error {
	for len(payload) > 0 {
		n := len(payload)
		if n > ssMaxChunk {
			n = ssMaxChunk
		}
		chunk := payload[:n]
		payload = payload[n:]

		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		sealedLen := s.seal(s.sendAEAD, &s.sendCounter, lenBuf[:])
		sealedPayload := s.seal(s.sendAEAD, &s.sendCounter, chunk)
		if _, err := s.Conn.Write(sealedLen); err != nil {
			return err
		}
		if _, err := s.Conn.Write(sealedPayload); err != nil {
			return err
		}
	}
	return nil
}

// readChunk reads and decrypts the next chunk, returning its plaintext.
func (s *ssConn) readChunk() ([]byte, error) {
	sealedLen := make([]byte, 2+s.recvAEAD.Overhead())
	if _, err := io.ReadFull(s.Conn, sealedLen); err != nil {
		return nil, err
	}
	lenPlain, err := s.open(s.recvAEAD, &s.recvCounter, sealedLen)
	if err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenPlain)

	sealedPayload := make([]byte, int(n)+s.recvAEAD.Overhead())
	if _, err := io.ReadFull(s.Conn, sealedPayload); err != nil {
		return nil, err
	}
	return s.open(s.recvAEAD, &s.recvCounter, sealedPayload)
}

func (s *ssConn) Read(p []byte) (int, error) {
	for len(s.recvBuf) == 0 {
		chunk, err := s.readChunk()
		if err != nil {
			return 0, err
		}
		s.recvBuf = chunk
	}
	n := copy(p, s.recvBuf)
	s.recvBuf = s.recvBuf[n:]
	return n, nil
}

func (s *ssConn) Write(p []byte) (int, error) {
	if err := s.writeChunk(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

var errSSAuthRejected = errors.New("carrier: shadowsocks-aead: server rejected auth frame")

// ssHandshakeClient performs the ephemeral-ECDH handshake and returns the
// wrapped AEAD connection plus a tunnel.Session ready for
// WriteConnect/WritePing, mirroring establish() in transport_plain.go /
// transport_reality.go.
func ssHandshakeClient(cfg Config) (*ssConn, *tunnel.Session, error) {
	serverPub, err := keys.DecodePublic(cfg.PubB64)
	if err != nil {
		return nil, nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ss, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, nil, err
	}
	k, err := newSSKeys(ss, serverPub.Bytes())
	if err != nil {
		return nil, nil, err
	}

	conn, err := net.Dial("tcp", cfg.Server)
	if err != nil {
		return nil, nil, err
	}
	if _, err := conn.Write(eph.PublicKey().Bytes()); err != nil {
		conn.Close()
		return nil, nil, err
	}
	sc := newSSConn(conn, k.c2s, k.s2c)

	// Auth frame: window || shortID, same anti-replay shape as
	// internal/auth.Seal's plaintext, just carried as the first AEAD chunk
	// instead of a ClientHello SessionID (there is no ClientHello here).
	authFrame := make([]byte, 8+ssShortIDLen)
	binary.BigEndian.PutUint64(authFrame[:8], uint64(time.Now().Unix()/ssWindowSeconds))
	copy(authFrame[8:], ParseShortID(cfg.ShortIDHex))
	if err := sc.writeChunk(authFrame); err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Capability token (ROADMAP2 §1), when set, rides the same raw AEAD-chunk
	// layer as the auth frame above -- deliberately NOT tunnel.Session's
	// WriteAuthToken/padding-frame layer, since that layer doesn't exist yet
	// at this point (it starts once the handshake below is fully accepted),
	// and mixing the two framings would desync the server's reader.
	if cfg.Token != "" {
		if err := sc.writeChunk([]byte(cfg.Token)); err != nil {
			conn.Close()
			return nil, nil, err
		}
		statusChunk, err := sc.readChunk()
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if len(statusChunk) != 1 || statusChunk[0] != 1 {
			conn.Close()
			return nil, nil, errSSAuthRejected
		}
	}

	sess := tunnel.ClientSession(ss)
	return sc, sess, nil
}

func ssDialConnect(cfg Config, host string, port uint16) (net.Conn, error) {
	sc, sess, err := ssHandshakeClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := sess.WriteConnect(sc, host, port); err != nil {
		sc.Close()
		return nil, err
	}
	ok, err := sess.ReadStatus(sc)
	if err != nil {
		sc.Close()
		return nil, err
	}
	if !ok {
		sc.Close()
		return nil, errors.New("carrier: shadowsocks-aead: server refused CONNECT")
	}
	return sc, nil
}

func ssPing(cfg Config) error {
	sc, sess, err := ssHandshakeClient(cfg)
	if err != nil {
		return err
	}
	defer sc.Close()
	if err := sess.WritePing(sc); err != nil {
		return err
	}
	_ = sc.SetReadDeadline(time.Now().Add(5 * time.Second))
	ok, err := sess.ReadStatus(sc)
	if err != nil {
		return err
	}
	if !ok {
		return errSSAuthRejected
	}
	return nil
}

func ssServe(ctx context.Context, cfg SSServerConfig) error {
	priv, err := keys.DecodePrivate(cfg.PrivB64)
	if err != nil {
		return err
	}
	serverPub := priv.PublicKey().Bytes()

	allowlist := cfg.Allowlist
	if allowlist == nil && cfg.TokenVerifier == nil {
		ids := make(StaticAllowlist, 0, len(cfg.ShortIDs))
		for _, id := range cfg.ShortIDs {
			ids = append(ids, ParseShortID(id))
		}
		allowlist = ids
	}

	rate, burst := cfg.AuthRate, cfg.AuthBurst
	if rate <= 0 {
		rate, burst = 50.0, 100.0
	}
	limiter := ratelimit.New(rate, burst)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	slog.Info("shadowsocks-aead carrier up", "listen", cfg.Listen)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go ssHandleConn(c, priv, serverPub, allowlist, cfg.TokenVerifier, limiter)
	}
}

func ssHandleConn(c net.Conn, priv *ecdh.PrivateKey, serverPub []byte, allowlist Allowlist, tokenVerifier TokenVerifier, limiter *ratelimit.Limiter) {
	defer c.Close()

	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	if !limiter.Allow(host) {
		return
	}

	ephPub := make([]byte, 32)
	if _, err := io.ReadFull(c, ephPub); err != nil {
		return
	}
	pub, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return
	}
	ss, err := priv.ECDH(pub)
	if err != nil {
		return
	}
	k, err := newSSKeys(ss, serverPub)
	if err != nil {
		return
	}
	// Server's view mirrors the client's: it receives on c2s, sends on s2c.
	sc := newSSConn(c, k.s2c, k.c2s)

	authFrame, err := sc.readChunk()
	if err != nil || len(authFrame) != 8+ssShortIDLen {
		return
	}
	window := binary.BigEndian.Uint64(authFrame[:8])
	now := uint64(time.Now().Unix() / ssWindowSeconds)
	if !(window == now || window+1 == now || window == now+1) {
		return // outside the anti-replay window
	}
	shortID := authFrame[8:]

	if tokenVerifier == nil {
		if !AllowlistOrAny(allowlist, shortID) {
			return
		}
	} else {
		// Mirrors the client's raw ssConn-chunk exchange in
		// ssHandshakeClient -- see that function's comment on why this
		// deliberately doesn't use tunnel.Session's own framing yet.
		token, err := sc.readChunk()
		if err != nil {
			return
		}
		ok := tokenVerifier.VerifyToken(string(token), hex.EncodeToString(shortID))
		status := byte(0)
		if ok {
			status = 1
		}
		if err := sc.writeChunk([]byte{status}); err != nil || !ok {
			return
		}
	}

	sess := tunnel.ServerSession(ss)
	ssServeTunnel(sc, sess)
}

// ssServeTunnel mirrors server.serveTunnel / internal/quic's serveTunnel --
// each transport keeps its own tiny copy of this dispatch loop rather than
// sharing one across packages, consistent with the existing TCP/QUIC split.
func ssServeTunnel(rw io.ReadWriteCloser, sess *tunnel.Session) {
	cmd, host, port, err := sess.ReadRequest(rw)
	if err != nil {
		return
	}
	if cmd == tunnel.CmdPing {
		_ = sess.WriteStatus(rw, true)
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = sess.WriteStatus(rw, false)
		return
	}
	defer target.Close()
	if err := sess.WriteStatus(rw, true); err != nil {
		return
	}
	go func() { _, _ = io.Copy(target, rw) }()
	_, _ = io.Copy(rw, target)
}
