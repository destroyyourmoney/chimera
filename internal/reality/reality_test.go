//go:build chimera_utls

package reality

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"chimera/internal/auth"
	"chimera/internal/clienthello"
)

// serverGate reproduces what internal/server does before ServerWrap: read the
// ClientHello record, recover the shared secret, and verify the auth tag.
func serverGate(t *testing.T, conn net.Conn, priv *ecdh.PrivateKey) (prefix, ss []byte, ok bool) {
	t.Helper()
	br := bufio.NewReader(conn)
	hdr, err := br.Peek(5)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	raw := make([]byte, 5+recLen)
	if _, err := io.ReadFull(br, raw); err != nil {
		t.Fatalf("read record: %v", err)
	}
	// Include any bytes bufio pulled past the ClientHello (e.g. the dummy CCS).
	if n := br.Buffered(); n > 0 {
		extra, _ := br.Peek(n)
		raw = append(raw, extra...)
		_, _ = br.Discard(n)
	}

	sid, xpub, perr := clienthello.Parse(raw)
	if perr != nil || len(xpub) != 32 || len(sid) < auth.TagLen {
		return raw, nil, false
	}
	pub, err := ecdh.X25519().NewPublicKey(xpub)
	if err != nil {
		return raw, nil, false
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return raw, nil, false
	}
	if _, good := auth.Open(secret, xpub, priv.PublicKey().Bytes(), sid[:auth.TagLen]); !good {
		return raw, nil, false
	}
	return raw, secret, true
}

func TestRealityRoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		prefix, ss, ok := serverGate(t, c, priv)
		if !ok {
			srvErr <- io.ErrUnexpectedEOF
			return
		}
		tc, err := ServerWrap(c, prefix, ss, "www.microsoft.com")
		if err != nil {
			srvErr <- err
			return
		}
		// Echo one framed message to prove the TLS channel carries data.
		buf := make([]byte, 5)
		if _, err := io.ReadFull(tc, buf); err != nil {
			srvErr <- err
			return
		}
		_, err = tc.Write(buf)
		srvErr <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tc, ss, err := ClientWrap(conn, priv.PublicKey(), "www.microsoft.com", "0a1b2c3d")
	if err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	if len(ss) == 0 {
		t.Fatal("client got empty shared secret")
	}

	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("hello")
	if _, err := tc.Write(msg); err != nil {
		t.Fatalf("write over TLS: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// TestRealityWrongServerKeyFails confirms a client pointed at the wrong server
// static key cannot complete the PSK confirmation (no oracle, just failure).
func TestRealityWrongServerKeyFails(t *testing.T) {
	realPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Server holds realPriv; gate will fail to open the tag (client used
		// wrongPriv's public), so it never reaches ServerWrap. Drain to EOF.
		_, _, ok := serverGate(t, c, realPriv)
		if ok {
			t.Error("server unexpectedly authenticated a mismatched key")
		}
		_, _ = io.Copy(io.Discard, c)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Client uses the WRONG server public key -> server cannot derive the same ss.
	if _, _, err := ClientWrap(conn, wrongPriv.PublicKey(), "www.microsoft.com", "0a1b2c3d"); err == nil {
		t.Fatal("ClientWrap should fail when server key does not match")
	}
}
