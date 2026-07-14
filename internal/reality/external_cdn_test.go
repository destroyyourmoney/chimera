//go:build chimera_utls

package reality

// Real-external-CDN validation for the ServerHello/JA3S parity engine
// (docs/reality-serverhello-engine.md, "Not yet done" gap #1). Every other
// test in this package validates against either this codebase's own parser
// (same-process round-trip) or a local, single-cert Go crypto/tls stand-in
// (chrome_vantage_test.go) -- neither exercises a real production CDN's TLS
// stack, session ticket behavior, or extension set, which can differ from a
// local stand-in's.
//
// This file probes and serves against a REAL external host over the public
// Internet. It never terminates or MITMs that host's TLS: the (optional)
// real-Chrome leg connects through a dumb byte-relay proxy (Chrome's
// --host-resolver-rules points the target hostname at 127.0.0.1:<proxy
// port>; the proxy just pipes bytes to and from the real host on 443
// unmodified), so Chrome's own certificate validation and the real CDN's
// handshake are completely undisturbed -- we only observe the wire bytes
// that already crossed the network, the same way chrome_vantage_test.go's
// recordingConn observes a local server's writes.
//
// Skipped unless CHIMERA_EXTERNAL_STEALHOST=host[:port] is set (default port
// 443). Also runs the real-Chrome leg (three-way comparison) if
// CHIMERA_CHROME_PATH additionally points at a real Chrome/Chromium binary;
// otherwise runs a two-way comparison (probe vs. CHIMERA-served) only. This
// test is a CANARY, not a hard CI gate: a real CDN's negotiated
// cipher/group/extension-order is operator infrastructure outside this
// repo's control and can legitimately change over time (see the recorded
// result in docs/reality-serverhello-engine.md).
//
// This is also where a real CDN can genuinely send a HelloRetryRequest (see
// probe.go's errHelloRetryRequest) if our probe's pinned ClientHello key_share
// doesn't happen to match the CDN's preferred group on a given run -- the
// local crypto/tls stand-in used elsewhere never does this. That is treated
// as an inconclusive run (t.Skip), not a failure: ServerWrap's own fail-open
// behavior on any probe error is what actually matters in production.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"testing"
	"time"

	"crypto/ecdh"
	"crypto/rand"
)

// syncBuffer is a concurrency-safe growable byte buffer: one goroutine
// writes (the relay's server->client copy), the test goroutine polls reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

// relayCapture tracks one syncBuffer per accepted proxy connection, in
// accept order, mirroring recordingListener's role in chrome_vantage_test.go
// but for a byte-relay proxy instead of a TLS-terminating listener.
type relayCapture struct {
	mu   sync.Mutex
	bufs []*syncBuffer
}

func (rc *relayCapture) add(b *syncBuffer) {
	rc.mu.Lock()
	rc.bufs = append(rc.bufs, b)
	rc.mu.Unlock()
}

func (rc *relayCapture) count() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.bufs)
}

func (rc *relayCapture) at(i int) []byte {
	rc.mu.Lock()
	b := rc.bufs[i]
	rc.mu.Unlock()
	return b.Bytes()
}

// startByteRelay listens on 127.0.0.1:0 and, for every accepted connection,
// dials realAddr and pipes bytes unmodified in both directions, recording
// what flows server->client into a fresh entry in rc. It never inspects,
// terminates, or modifies TLS in any way -- purely a transparent TCP pipe
// with a tap on one direction.
func startByteRelay(t *testing.T, realAddr string, rc *relayCapture) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				server, err := net.DialTimeout("tcp", realAddr, 10*time.Second)
				if err != nil {
					client.Close()
					return
				}
				buf := &syncBuffer{}
				rc.add(buf)
				go func() {
					_, _ = io.Copy(server, client)
					server.Close()
				}()
				_, _ = io.Copy(io.MultiWriter(client, buf), server)
				client.Close()
			}(client)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

// waitForRelayedServerHello polls rc's first captured connection until a
// complete ServerHello handshake message has flowed through, or the
// deadline elapses.
func waitForRelayedServerHello(rc *relayCapture, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rc.count() > 0 {
			if raw, err := readServerHelloMessage(bytes.NewReader(rc.at(0))); err == nil {
				return raw, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if rc.count() == 0 {
		return nil, errors.New("no connection ever reached the relay proxy")
	}
	return readServerHelloMessage(bytes.NewReader(rc.at(0)))
}

// runHeadlessChromeThroughRelay navigates chromePath to url, forcing host
// (the hostname in url) to resolve to the relay proxy address instead of via
// real DNS -- Chrome still uses host as SNI/Host header and validates the
// real CDN's certificate against it normally, since the relay is a
// transparent pipe to the real host:443.
func runHeadlessChromeThroughRelay(t *testing.T, chromePath, url, host, proxyAddr string, rc *relayCapture) {
	t.Helper()
	profile := t.TempDir()

	args := []string{
		"--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
		"--no-first-run", "--no-default-browser-check",
		"--disable-background-networking",
		"--host-resolver-rules=MAP " + host + " " + proxyAddr,
		"--user-data-dir=" + profile,
		url,
	}
	cmd := exec.Command(chromePath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start chrome: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(30 * time.Second)
	for rc.count() == 0 && time.Now().Before(deadline) {
		select {
		case <-done:
			goto afterWait
		case <-time.After(200 * time.Millisecond):
		}
	}
afterWait:
	killProcessTree(cmd.Process.Pid)
	<-done

	if rc.count() == 0 {
		t.Fatalf("chrome never connected via relay to %s; stderr:\n%s", url, stderr.String())
	}
}

// TestExternalCDNServerHelloParity validates the probe/template/serve
// pipeline against a real external steal-host over the public Internet.
func TestExternalCDNServerHelloParity(t *testing.T) {
	target := os.Getenv("CHIMERA_EXTERNAL_STEALHOST")
	if target == "" {
		t.Skip("CHIMERA_EXTERNAL_STEALHOST not set; skipping real-external-CDN validation")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	stealHostAddr := net.JoinHostPort(host, port)

	// Force a fresh probe rather than reusing anything another test in this
	// package cached for the same host name.
	probeCache.mu.Lock()
	delete(probeCache.m, host)
	probeCache.mu.Unlock()

	// --- Leg A: CHIMERA's own probe against the real external host ---
	dial := func() (net.Conn, error) { return net.DialTimeout("tcp", stealHostAddr, 10*time.Second) }
	shProbe, err := ProbeServerHello(dial, host)
	if errors.Is(err, errHelloRetryRequest) {
		t.Skipf("real CDN %s sent a HelloRetryRequest to our probe's ClientHello -- "+
			"inconclusive run, not a failure (see errHelloRetryRequest doc comment); re-run to retry", stealHostAddr)
	}
	if err != nil {
		t.Fatalf("ProbeServerHello against %s: %v", stealHostAddr, err)
	}
	t.Logf("real CDN %s probe ServerHello: cipher=%#04x group=%#04x extensions=%v",
		stealHostAddr, shProbe.CipherSuite, shProbe.KeyShareGroup, extTypes(shProbe))

	// --- Leg B: CHIMERA's authorized-session served ServerHello, end to end.
	// Seed the cache with Leg A's already-captured template instead of letting
	// ServerWrap's internal probe dial the real CDN a second time: a second
	// live probe could legitimately negotiate something different (e.g. the
	// CDN issuing an HRR the second time, or routing to a different edge
	// node), which would be real-world noise, not a bug in the pipeline this
	// test is trying to validate. ---
	probeCache.mu.Lock()
	probeCache.m[host] = templateCacheEntry{tmpl: shProbe, at: time.Now()}
	probeCache.mu.Unlock()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chimeraLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer chimeraLn.Close()

	var chimeraRec *recordingConn
	srvErr := make(chan error, 1)
	go func() {
		c, err := chimeraLn.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		chimeraRec = &recordingConn{Conn: c}
		prefix, ss, ok := serverGate(t, chimeraRec, priv)
		if !ok {
			srvErr <- io.ErrUnexpectedEOF
			return
		}
		tc, err := ServerWrap(chimeraRec, prefix, ss, stealHostAddr)
		if err != nil {
			srvErr <- err
			return
		}
		defer tc.Close()
		srvErr <- nil
	}()

	conn, err := net.Dial("tcp", chimeraLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := ClientWrap(conn, priv.PublicKey(), host, "0a1b2c3d"); err != nil {
		t.Fatalf("ClientWrap: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}

	chimeraRaw, err := readServerHelloMessage(bytes.NewReader(chimeraRec.written()))
	if err != nil {
		t.Fatalf("extract CHIMERA-served ServerHello: %v", err)
	}
	shChimera, err := ParseServerHello(chimeraRaw)
	if err != nil {
		t.Fatalf("parse CHIMERA-served ServerHello: %v", err)
	}
	t.Logf("CHIMERA-served ServerHello (steal-host=%s): cipher=%#04x group=%#04x extensions=%v",
		stealHostAddr, shChimera.CipherSuite, shChimera.KeyShareGroup, extTypes(shChimera))

	if shChimera.CipherSuite != shProbe.CipherSuite {
		t.Errorf("CHIMERA-served cipher = %#04x, want probe ground truth %#04x", shChimera.CipherSuite, shProbe.CipherSuite)
	}
	if shChimera.KeyShareGroup != shProbe.KeyShareGroup {
		t.Errorf("CHIMERA-served group = %#04x, want probe ground truth %#04x", shChimera.KeyShareGroup, shProbe.KeyShareGroup)
	}
	if !reflect.DeepEqual(extTypes(shChimera), extTypes(shProbe)) {
		t.Errorf("CHIMERA-served extension order = %v, want probe ground truth %v", extTypes(shChimera), extTypes(shProbe))
	}

	// --- Leg C (optional): a real headless Chrome talking to the SAME real
	// external host through a transparent byte-relay, for a genuine
	// independent-implementation three-way comparison. ---
	chromePath := os.Getenv("CHIMERA_CHROME_PATH")
	if chromePath == "" {
		t.Log("CHIMERA_CHROME_PATH not set; skipping real-Chrome leg (two-way probe-vs-served comparison above still ran)")
		return
	}
	if _, err := os.Stat(chromePath); err != nil {
		t.Fatalf("CHIMERA_CHROME_PATH %q: %v", chromePath, err)
	}

	rc := &relayCapture{}
	relayLn := startByteRelay(t, stealHostAddr, rc)
	proxyAddr := relayLn.Addr().String()

	url := fmt.Sprintf("https://%s/", host)
	runHeadlessChromeThroughRelay(t, chromePath, url, host, proxyAddr, rc)

	chromeRaw, err := waitForRelayedServerHello(rc, 15*time.Second)
	if err != nil {
		t.Fatalf("extract real-Chrome ServerHello via relay: %v", err)
	}
	shChrome, err := ParseServerHello(chromeRaw)
	if errors.Is(err, errHelloRetryRequest) {
		t.Skipf("real CDN %s sent a HelloRetryRequest to real Chrome -- inconclusive run", stealHostAddr)
	}
	if err != nil {
		t.Fatalf("parse real-Chrome ServerHello: %v", err)
	}
	t.Logf("real Chrome ServerHello (via %s): cipher=%#04x group=%#04x extensions=%v",
		stealHostAddr, shChrome.CipherSuite, shChrome.KeyShareGroup, extTypes(shChrome))

	if shProbe.CipherSuite != shChrome.CipherSuite {
		t.Errorf("probe cipher = %#04x, want real-Chrome ground truth %#04x", shProbe.CipherSuite, shChrome.CipherSuite)
	}
	if shProbe.KeyShareGroup != shChrome.KeyShareGroup {
		t.Errorf("probe group = %#04x, want real-Chrome ground truth %#04x", shProbe.KeyShareGroup, shChrome.KeyShareGroup)
	}
	if !reflect.DeepEqual(extTypes(shProbe), extTypes(shChrome)) {
		t.Errorf("probe extension order = %v, want real-Chrome ground truth %v", extTypes(shProbe), extTypes(shChrome))
	}

	if shChimera.CipherSuite != shChrome.CipherSuite {
		t.Errorf("CHIMERA-served cipher = %#04x, want real-Chrome ground truth %#04x", shChimera.CipherSuite, shChrome.CipherSuite)
	}
	if shChimera.KeyShareGroup != shChrome.KeyShareGroup {
		t.Errorf("CHIMERA-served group = %#04x, want real-Chrome ground truth %#04x", shChimera.KeyShareGroup, shChrome.KeyShareGroup)
	}
	if !reflect.DeepEqual(extTypes(shChimera), extTypes(shChrome)) {
		t.Errorf("CHIMERA-served extension order = %v, want real-Chrome ground truth %v", extTypes(shChimera), extTypes(shChrome))
	}
}
