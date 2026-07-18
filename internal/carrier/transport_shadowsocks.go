//go:build chimera_ss

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
	ssWindowSeconds = 120
	ssShortIDLen    = 4
	ssMaxChunk      = 0x3FFF
)

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

type ssKeys struct {
	c2s cipher.AEAD
	s2c cipher.AEAD
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

type ssConn struct {
	net.Conn
	sendAEAD, recvAEAD cipher.AEAD
	sendCounter        uint64
	recvCounter        uint64
	recvBuf            []byte
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

	conn, err := net.DialTimeout("tcp", cfg.Server, DialTimeout)
	if err != nil {
		return nil, nil, err
	}
	if _, err := conn.Write(eph.PublicKey().Bytes()); err != nil {
		conn.Close()
		return nil, nil, err
	}
	sc := newSSConn(conn, k.c2s, k.s2c)

	authFrame := make([]byte, 8+ssShortIDLen)
	binary.BigEndian.PutUint64(authFrame[:8], uint64(time.Now().Unix()/ssWindowSeconds))
	copy(authFrame[8:], ParseShortID(cfg.ShortIDHex))
	if err := sc.writeChunk(authFrame); err != nil {
		conn.Close()
		return nil, nil, err
	}

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

	sc := newSSConn(c, k.s2c, k.c2s)

	authFrame, err := sc.readChunk()
	if err != nil || len(authFrame) != 8+ssShortIDLen {
		return
	}
	window := binary.BigEndian.Uint64(authFrame[:8])
	now := uint64(time.Now().Unix() / ssWindowSeconds)
	if !(window == now || window+1 == now || window == now+1) {
		return
	}
	shortID := authFrame[8:]

	if tokenVerifier == nil {
		if !AllowlistOrAny(allowlist, shortID) {
			return
		}
	} else {

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

func ssServeTunnel(rw io.ReadWriteCloser, sess *tunnel.Session) {
	cmd, host, port, err := sess.ReadRequest(rw)
	if err != nil {
		return
	}
	if cmd == tunnel.CmdPing {
		_ = sess.WriteStatus(rw, true)
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), DialTimeout)
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
