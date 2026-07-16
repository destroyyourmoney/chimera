//go:build chimera_dot

// DNS-over-TCP carrier (ROADMAP2 §3): promotes the DNS-over-TCP fallback
// already used internally for DNS resolution (internal/netstack's
// relayDNSOverTCP, added for the "connected but nothing resolves" fix) to a
// standalone, user-selectable anti-censorship transport. Unlike that
// fallback -- which speaks *real* DNS-over-TCP to resolve *real* domain
// names for the tunnel's own DNS traffic -- this transport disguises the
// CHIMERA handshake and tunnel itself as a stream of DNS-over-TCP
// query/response messages (RFC 7766 framing: 2-byte length + message)
// between client and server, carrying the actual encrypted payload inside
// each message's EDNS0 OPT pseudo-record (RFC 6891) as a private-use
// option.
//
// Honest compromise, matching the caveat pattern in transport_shadowsocks.go:
// this discipline is framing-level, not turn-perfect protocol emulation --
// the server may send several "response"-shaped messages with self-chosen
// IDs without a strict 1:1 query/response pairing, so it can push downlink
// data whenever it has some rather than only in reply to a client query.
// A sophisticated DPI box correlating query/response ID pairs over time
// could in principle notice this; documented here rather than glossed
// over, same spirit as ROADMAP2 §0.1 п.3. Positioning (see
// anticensorship_page.dart): slower than the other three, but blocking
// DNS-over-TCP outright breaks the censor's own network too.
//
// FIXED (previously logged here as a KNOWN ISSUE against docker/bench.sh):
// root cause was a plain return-value bug in dotConn.Write, not a
// connection-teardown/RST timing issue as first suspected. The loop drains
// its local `p` slice down to zero length via `p = p[n:]` and then returned
// `len(p)` (always 0) instead of the original input length. Every relay of
// more than a trickle of data goes through io.Copy, which treats any
// Write() returning fewer bytes than requested as io.ErrShortWrite and
// aborts the copy immediately -- even though every byte had, in fact, already
// been written correctly onto the wire (confirmed by instrumenting both
// sides: the full payload always arrived intact before the abort). This is
// also why the earlier byte-for-byte diff came back clean -- the data that
// *did* get copied was never corrupted, only truncated by the premature
// abort. Fixed by capturing the original length in `total` before the loop
// and returning that. dotServeTunnel's wait-for-both-directions/CloseWrite
// half-close (below) is kept as a defensive belt-and-suspenders shutdown
// discipline, matching the pattern documented on it, even though it was not
// itself the fix for this bug.
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
	dotMaxChunk      = 1200 // keeps each DNS message a plausible size over TCP
	// dotOptionCode is a private/experimental EDNS0 option code (RFC 6891
	// reserves 65001-65534 for local/experimental use) carrying the actual
	// encrypted payload chunk.
	dotOptionCode = 65001
)

// --- minimal HKDF-SHA256 (RFC 5869) -- see transport_shadowsocks.go's
// identical comment on why this is duplicated per-transport rather than
// shared: each transport file stays fully self-contained. ---

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

// dotConn wraps a raw net.Conn with DNS-over-TCP message framing. Each
// Write is chunked into one or more DNS messages (query-shaped if isClient,
// response-shaped otherwise) whose OPT option carries an AEAD-sealed
// payload chunk; each Read parses the next length-prefixed DNS message off
// the wire and returns its decrypted option payload. tunnel.Session's own
// padded control-frame protocol rides on top of this unchanged, exactly as
// it does on the other three transports.
type dotConn struct {
	net.Conn
	isClient             bool
	queryName            dnsmessage.Name
	sendAEAD, recvAEAD   cipher.AEAD
	sendCounter          uint64
	recvCounter          uint64
	recvBuf              []byte
}

func newDotConn(c net.Conn, isClient bool, queryName dnsmessage.Name, sendAEAD, recvAEAD cipher.AEAD) *dotConn {
	return &dotConn{Conn: c, isClient: isClient, queryName: queryName, sendAEAD: sendAEAD, recvAEAD: recvAEAD}
}

func (d *dotConn) nonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

// writeMessage seals payload and wraps it in one DNS message, framed with
// the RFC 7766 2-byte length prefix.
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

// readMessage reads one length-prefixed DNS message and returns its
// decrypted OPT option payload.
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

// CloseWrite forwards a half-close to the embedded connection when it
// supports one (e.g. *net.TCPConn) -- lets a relay signal "no more data
// coming" with a clean FIN instead of only a full Close().
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

	conn, err := net.Dial("tcp", cfg.Server)
	if err != nil {
		return nil, nil, err
	}
	qname := dotQueryName(cfg.SNI)
	dc := newDotConn(conn, true, qname, k.c2s, k.s2c)

	// Message 1: raw ephemeral pubkey, cleartext by necessity (the server
	// can't derive keys before it has this), carried as an otherwise
	// unauthenticated OPT payload -- the AEAD-sealed auth frame right
	// after is what actually proves anything.
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

// writeMessageRaw sends payload as a DNS message's OPT option WITHOUT AEAD
// sealing -- used only for the very first message (the ephemeral pubkey),
// before either side has derived a shared key.
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

// readMessageRaw reads one DNS message and returns its OPT payload without
// attempting AEAD decryption -- the server-side counterpart to
// writeMessageRaw, used only to read the client's very first message.
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

	// dc is constructed with placeholder AEAD ciphers (nil) until keys are
	// derived below; readMessageRaw/writeMessageRaw don't touch them.
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

// dotServeTunnel mirrors ssServeTunnel/server.serveTunnel, with one
// deliberate difference that fixes the KNOWN ISSUE documented at the top of
// this file: ssServeTunnel/server.serveTunnel return (and let their caller's
// deferred Close run) as soon as the FIRST of the two copy directions
// finishes, leaving the other goroutine's Read still pending against the
// connection that's about to be closed. On a raw byte-stream transport that
// race is usually harmless; on dot's message-framed conn it reliably
// produced a hard TCP close (RST, discarding any not-yet-acked bytes still
// in flight) instead of a clean shutdown, right around the final
// chunked-encoding boundary -- matching the observed curl exit 18 exactly.
// Fix: half-close each direction with CloseWrite (a clean FIN) as it
// finishes, and only fully Close once BOTH directions have drained.
func dotServeTunnel(rw io.ReadWriteCloser, sess *tunnel.Session) {
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
