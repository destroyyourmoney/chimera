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

// recordingConn wraps a net.Conn and mirrors everything written to it into a
// buffer, so a test can inspect the exact bytes the server put on the wire.
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

// TestServerWrap_AppliesServerHelloShape proves the wiring from a
// ServerHelloTemplate (as ServerHelloTemplateFor would return from a real
// probe) through to the literal bytes ServerWrap puts on the wire: forced
// cipher suite and a non-default extension order both take effect, and the
// PSK-authenticated handshake still completes successfully (ROADMAP Этап 1b
// Phase 2/3: docs/reality-serverhello-engine.md).
func TestServerWrap_AppliesServerHelloShape(t *testing.T) {
	const sni = "shape.test"

	// TLS_CHACHA20_POLY1305_SHA256: real Chrome offers it but it is not
	// Go's own top preference (AES-GCM usually wins when hardware-accelerated),
	// so forcing it is a real, observable behavior change, not a coincidence.
	const forcedCipher = 0x1303
	const forcedGroup = 0x001d // x25519 -- the only group CurvePreferences allows here

	// Seed the cache directly (same package) with a synthetic template whose
	// extension order is the REVERSE of the stack's hardcoded default
	// (key_share before supported_versions), so a match proves templating
	// actually drove the marshal, not the pre-existing default order.
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
		// No port on purpose: dial must never actually be attempted since
		// the cache is pre-seeded above -- if it were, this would be an
		// immediate local "missing port" error anyway, never real network I/O.
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

// TestServerWrap_ForcesHybridGroup proves ForceGroup can steer the live TLS
// negotiation to the X25519MLKEM768 hybrid group (as a template captured
// from a PQ-preferring real steal-host would), and that the ss-based PSK
// auth still completes -- ss is derived from the ClientHello's plain X25519
// key_share entry independently of whatever group the TLS layer negotiates
// (docs/reality-serverhello-engine.md Phase 4 note; see CurvePreferences'
// comment in ServerWrap).
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

// TestServerWrap_NoTemplateFallsBackToDefault confirms that when no template
// is cached and the probe dial fails (as it always will here -- nothing
// listens on the chosen port), ServerWrap still produces a valid TLS 1.3
// handshake using the stack's stock ordering, rather than failing the
// session. This is the safety net documented in
// docs/reality-serverhello-engine.md §9/§10.
func TestServerWrap_NoTemplateFallsBackToDefault(t *testing.T) {
	// Loopback with nothing listening -> the probe dial fails fast
	// (connection refused) with no DNS lookup involved.
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
		// Nothing listens on stealHostAddr, forcing the internal probe dial
		// to fail and exercising the nil-shape fallback path.
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
