//go:build chimera_dot

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
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"chimera/internal/keys"
	"chimera/internal/ratelimit"
	"chimera/internal/tunnel"
)

func init() {
	DoTDialConnect = dotDialConnect
	DoTPing = dotPing
	DoTServe = dotServe
}

const (
	dotWindowSeconds = 120
	dotShortIDLen    = 4
	dotMaxChunk      = 1200

	dotOptionCode = 65001
)

func dotHkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func dotHkdfExpand(prk, info []byte, n int) []byte {
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

func dotDeriveKey(ss, salt []byte, info string) []byte {
	prk := dotHkdfExtract(salt, ss)
	return dotHkdfExpand(prk, []byte(info), 32)
}

type dotKeys struct {
	c2s cipher.AEAD
	s2c cipher.AEAD
}

func newDotKeys(ss, serverPub []byte) (dotKeys, error) {
	c2sKey := dotDeriveKey(ss, serverPub, "chimera-dot-v0-c2s")
	s2cKey := dotDeriveKey(ss, serverPub, "chimera-dot-v0-s2c")
	c2s, err := dotNewGCM(c2sKey)
	if err != nil {
		return dotKeys{}, err
	}
	s2c, err := dotNewGCM(s2cKey)
	if err != nil {
		return dotKeys{}, err
	}
	return dotKeys{c2s: c2s, s2c: s2c}, nil
}

func dotNewGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type dotConn struct {
	net.Conn
	isClient           bool
	queryName          dnsmessage.Name
	sendAEAD, recvAEAD cipher.AEAD
	sendCounter        uint64
	recvCounter        uint64
	recvBuf            []byte
}

func newDotConn(c net.Conn, isClient bool, queryName dnsmessage.Name, sendAEAD, recvAEAD cipher.AEAD) *dotConn {
	return &dotConn{Conn: c, isClient: isClient, queryName: queryName, sendAEAD: sendAEAD, recvAEAD: recvAEAD}
}

func (d *dotConn) nonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func (d *dotConn) writeMessage(payload []byte) error {
	sealed := d.sendAEAD.Seal(nil, d.nonce(d.sendCounter), payload, nil)
	d.sendCounter++

	var msg dnsmessage.Message
	id := uint16(time.Now().UnixNano())
	msg.Header = dnsmessage.Header{ID: id, Response: !d.isClient, RecursionDesired: d.isClient, RecursionAvailable: !d.isClient}
	msg.Questions = []dnsmessage.Question{{Name: d.queryName, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}
	msg.Additionals = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096},
		Body:   &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: dotOptionCode, Data: sealed}}},
	}}
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := d.Conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = d.Conn.Write(packed)
	return err
}

func (d *dotConn) readMessage() ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(d.Conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	raw := make([]byte, n)
	if _, err := io.ReadFull(d.Conn, raw); err != nil {
		return nil, err
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, err
	}
	for _, add := range msg.Additionals {
		opt, ok := add.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, o := range opt.Options {
			if o.Code != dotOptionCode {
				continue
			}
			out, err := d.recvAEAD.Open(nil, d.nonce(d.recvCounter), o.Data, nil)
			if err != nil {
				return nil, err
			}
			d.recvCounter++
			return out, nil
		}
	}
	return nil, errDotNoPayload
}

func (d *dotConn) Read(p []byte) (int, error) {
	for len(d.recvBuf) == 0 {
		chunk, err := d.readMessage()
		if err != nil {
			return 0, err
		}
		d.recvBuf = chunk
	}
	n := copy(p, d.recvBuf)
	d.recvBuf = d.recvBuf[n:]
	return n, nil
}

func (d *dotConn) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > dotMaxChunk {
			n = dotMaxChunk
		}
		if err := d.writeMessage(p[:n]); err != nil {
			return total - len(p), err
		}
		p = p[n:]
	}
	return total, nil
}

func (d *dotConn) CloseWrite() error {
	if cw, ok := d.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

var (
	errDotNoPayload    = errors.New("carrier: dns-over-tcp: message carried no recognizable payload option")
	errDotAuthRejected = errors.New("carrier: dns-over-tcp: server rejected auth/token")
)

func dotQueryName(sni string) dnsmessage.Name {
	name := sni
	if name == "" {
		name = "www.example.com"
	}
	if name[len(name)-1] != '.' {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.MustNewName("www.example.com.")
	}
	return n
}

func dotHandshakeClient(cfg Config) (*dotConn, *tunnel.Session, error) {
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
	k, err := newDotKeys(ss, serverPub.Bytes())
	if err != nil {
		return nil, nil, err
	}

	conn, err := net.DialTimeout("tcp", cfg.Server, DialTimeout)
	if err != nil {
		return nil, nil, err
	}
	qname := dotQueryName(cfg.SNI)
	dc := newDotConn(conn, true, qname, k.c2s, k.s2c)

	if err := dc.writeMessageRaw(eph.PublicKey().Bytes()); err != nil {
		conn.Close()
		return nil, nil, err
	}

	authFrame := make([]byte, 8+dotShortIDLen)
	binary.BigEndian.PutUint64(authFrame[:8], uint64(time.Now().Unix()/dotWindowSeconds))
	copy(authFrame[8:], ParseShortID(cfg.ShortIDHex))
	if err := dc.writeMessage(authFrame); err != nil {
		conn.Close()
		return nil, nil, err
	}

	if cfg.Token != "" {
		if err := dc.writeMessage([]byte(cfg.Token)); err != nil {
			conn.Close()
			return nil, nil, err
		}
		status, err := dc.readMessage()
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if len(status) != 1 || status[0] != 1 {
			conn.Close()
			return nil, nil, errDotAuthRejected
		}
	}

	sess := tunnel.ClientSession(ss)
	return dc, sess, nil
}

func (d *dotConn) writeMessageRaw(payload []byte) error {
	var msg dnsmessage.Message
	msg.Header = dnsmessage.Header{ID: uint16(time.Now().UnixNano()), Response: !d.isClient, RecursionDesired: d.isClient}
	msg.Questions = []dnsmessage.Question{{Name: d.queryName, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}
	msg.Additionals = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096},
		Body:   &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: dotOptionCode, Data: payload}}},
	}}
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := d.Conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = d.Conn.Write(packed)
	return err
}

func (d *dotConn) readMessageRaw() ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(d.Conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	raw := make([]byte, n)
	if _, err := io.ReadFull(d.Conn, raw); err != nil {
		return nil, err
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, err
	}
	for _, add := range msg.Additionals {
		if opt, ok := add.Body.(*dnsmessage.OPTResource); ok {
			for _, o := range opt.Options {
				if o.Code == dotOptionCode {
					return o.Data, nil
				}
			}
		}
	}
	return nil, errDotNoPayload
}

func dotDialConnect(cfg Config, host string, port uint16) (net.Conn, error) {
	dc, sess, err := dotHandshakeClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := sess.WriteConnect(dc, host, port); err != nil {
		dc.Close()
		return nil, err
	}
	ok, err := sess.ReadStatus(dc)
	if err != nil {
		dc.Close()
		return nil, err
	}
	if !ok {
		dc.Close()
		return nil, errors.New("carrier: dns-over-tcp: server refused CONNECT")
	}
	return dc, nil
}

func dotPing(cfg Config) error {
	dc, sess, err := dotHandshakeClient(cfg)
	if err != nil {
		return err
	}
	defer dc.Close()
	if err := sess.WritePing(dc); err != nil {
		return err
	}
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	ok, err := sess.ReadStatus(dc)
	if err != nil {
		return err
	}
	if !ok {
		return errDotAuthRejected
	}
	return nil
}

func dotServe(ctx context.Context, cfg DoTServerConfig) error {
	priv, err := keys.DecodePrivate(cfg.PrivB64)
	if err != nil {
		return err
	}
	serverPub := priv.PublicKey().Bytes()
	qname := dotQueryName(cfg.SNI)

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
	slog.Info("dns-over-tcp carrier up", "listen", cfg.Listen)

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
		go dotHandleConn(c, priv, serverPub, qname, allowlist, cfg.TokenVerifier, limiter)
	}
}

func dotHandleConn(c net.Conn, priv *ecdh.PrivateKey, serverPub []byte, qname dnsmessage.Name, allowlist Allowlist, tokenVerifier TokenVerifier, limiter *ratelimit.Limiter) {
	defer c.Close()

	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	if !limiter.Allow(host) {
		return
	}

	dc := &dotConn{Conn: c, isClient: false, queryName: qname}

	ephPub, err := dc.readMessageRaw()
	if err != nil || len(ephPub) != 32 {
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
	k, err := newDotKeys(ss, serverPub)
	if err != nil {
		return
	}
	dc.sendAEAD, dc.recvAEAD = k.s2c, k.c2s

	authFrame, err := dc.readMessage()
	if err != nil || len(authFrame) != 8+dotShortIDLen {
		return
	}
	window := binary.BigEndian.Uint64(authFrame[:8])
	now := uint64(time.Now().Unix() / dotWindowSeconds)
	if !(window == now || window+1 == now || window == now+1) {
		return
	}
	shortID := authFrame[8:]

	if tokenVerifier == nil {
		if !AllowlistOrAny(allowlist, shortID) {
			return
		}
	} else {
		token, err := dc.readMessage()
		if err != nil {
			return
		}
		ok := tokenVerifier.VerifyToken(string(token), hex.EncodeToString(shortID))
		status := byte(0)
		if ok {
			status = 1
		}
		if err := dc.writeMessage([]byte{status}); err != nil || !ok {
			return
		}
	}

	sess := tunnel.ServerSession(ss)
	dotServeTunnel(dc, sess)
}

func dotServeTunnel(rw io.ReadWriteCloser, sess *tunnel.Session) {
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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, rw)
		if cw, ok := target.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(rw, target)
		if cw, ok := rw.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}
