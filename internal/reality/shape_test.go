//go:build chimera_utls

package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recordingConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(b)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func (r *recordingConn) written() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

func TestServerWrap_AppliesServerHelloShape(t *testing.T) {
	const sni = "shape.test"

	const forcedCipher = 0x1303
	const forcedGroup = 0x001d

	probeCache.mu.Lock()
	probeCache.m[sni] = templateCacheEntry{
		tmpl: &ServerHelloTemplate{
			CipherSuite:   forcedCipher,
			KeyShareGroup: forcedGroup,
			Extensions: []ExtensionRecord{
				{Type: extensionKeyShare},
				{Type: extensionSupportedVersionsType},
			},
			CapturedAt: time.Now(),
		},
		at: time.Now(),
	}
	probeCache.mu.Unlock()
	t.Cleanup(func() {
		probeCache.mu.Lock()
		delete(probeCache.m, sni)
		probeCache.mu.Unlock()
	})

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var rec *recordingConn
	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		rec = &recordingConn{Conn: c}
		prefix, ss, ok := serverGate(t, rec, priv)
		if !ok {
			srvErr <- io.ErrUnexpectedEOF
			return
		}

		tc, err := ServerWrap(rec, prefix, ss, sni)
		if err != nil {
			srvErr <- err
			return
		}
		defer tc.Close()
		srvErr <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, _, err = ClientWrap(conn, priv.PublicKey(), sni, "0a1b2c3d")
	if err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}

	raw, err := readServerHelloMessage(bytes.NewReader(rec.written()))
	if err != nil {
		t.Fatalf("extract ServerHello from wire bytes: %v", err)
	}
	tmpl, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}

	if tmpl.CipherSuite != forcedCipher {
		t.Errorf("CipherSuite = %#04x, want forced %#04x", tmpl.CipherSuite, forcedCipher)
	}
	if tmpl.KeyShareGroup != forcedGroup {
		t.Errorf("KeyShareGroup = %#04x, want %#04x", tmpl.KeyShareGroup, forcedGroup)
	}
	if len(tmpl.Extensions) != 2 {
		t.Fatalf("Extensions = %d entries, want 2", len(tmpl.Extensions))
	}
	if tmpl.Extensions[0].Type != extensionKeyShare || tmpl.Extensions[1].Type != extensionSupportedVersionsType {
		t.Errorf("extension order = %#04x, %#04x; want key_share(0x33) then supported_versions(0x2b) per the pinned template",
			tmpl.Extensions[0].Type, tmpl.Extensions[1].Type)
	}
}

func TestServerWrap_ForcesHybridGroup(t *testing.T) {
	const sni = "hybrid.test"
	const x25519MLKEM768 = 4588

	probeCache.mu.Lock()
	probeCache.m[sni] = templateCacheEntry{
		tmpl: &ServerHelloTemplate{
			KeyShareGroup: x25519MLKEM768,
			CapturedAt:    time.Now(),
		},
		at: time.Now(),
	}
	probeCache.mu.Unlock()
	t.Cleanup(func() {
		probeCache.mu.Lock()
		delete(probeCache.m, sni)
		probeCache.mu.Unlock()
	})

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var rec *recordingConn
	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		rec = &recordingConn{Conn: c}
		prefix, ss, ok := serverGate(t, rec, priv)
		if !ok {
			srvErr <- io.ErrUnexpectedEOF
			return
		}
		tc, err := ServerWrap(rec, prefix, ss, sni)
		if err != nil {
			srvErr <- err
			return
		}
		defer tc.Close()
		srvErr <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, _, err := ClientWrap(conn, priv.PublicKey(), sni, "0a1b2c3d"); err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side (ss-based confirm must still succeed regardless of negotiated group): %v", err)
	}

	raw, err := readServerHelloMessage(bytes.NewReader(rec.written()))
	if err != nil {
		t.Fatalf("extract ServerHello from wire bytes: %v", err)
	}
	tmpl, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	if tmpl.KeyShareGroup != x25519MLKEM768 {
		t.Errorf("KeyShareGroup = %#04x, want forced %#04x (X25519MLKEM768)", tmpl.KeyShareGroup, x25519MLKEM768)
	}
}

func TestServerWrap_NoTemplateFallsBackToDefault(t *testing.T) {

	const stealHostAddr = "127.0.0.1:1"
	const sni = "127.0.0.1"

	probeCache.mu.Lock()
	delete(probeCache.m, sni)
	probeCache.mu.Unlock()

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

		tc, err := ServerWrap(c, prefix, ss, stealHostAddr)
		if err != nil {
			srvErr <- err
			return
		}
		defer tc.Close()
		srvErr <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, _, err := ClientWrap(conn, priv.PublicKey(), sni, "0a1b2c3d"); err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}
