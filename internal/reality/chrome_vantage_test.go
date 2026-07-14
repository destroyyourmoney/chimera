//go:build chimera_utls

package reality

// Real-Chrome vantage validation for the ServerHello/JA3S parity engine
// (docs/reality-serverhello-engine.md). Every other test in this package
// validates the probe/shape machinery against itself (this codebase's own
// parser, its own uTLS-driven ClientHello) -- a same-process round-trip.
// This file instead asks the question that matters: does a REAL Chrome
// (BoringSSL) TLS stack, talking to an ordinary TLS 1.3 server, get the same
// ServerHello shape (cipher suite, negotiated group, extension order) that
// CHIMERA's probe captures with its impersonated ClientHello -- and does
// CHIMERA's own served (authorized-session) ServerHello then match that
// real-Chrome ground truth too.
//
// No OS-level packet capture tool is used or needed (this dev box has no
// tshark/npcap/pktmon-for-loopback available -- confirmed empirically, same
// constraint noted in docs/uquic-initial-fingerprint.md for the QUIC engine).
// Ground truth instead comes from wrapping the local test server's accepted
// net.Conn to record exactly what it wrote, for both the real-Chrome
// connection and CHIMERA's own -- an application-level capture of a genuine,
// independent, external TLS implementation's output.
//
// Skipped unless CHIMERA_CHROME_PATH points at a real Chrome/Chromium binary,
// e.g. a Chrome for Testing build (https://googlechromelabs.github.io/chrome-for-testing/),
// installable with: npx @puppeteer/browsers install chrome@stable --path <dir>

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"testing"
	"time"
)

// recordingListener wraps a net.Listener and keeps every accepted connection
// wrapped in a recordingConn (defined in shape_test.go), in accept order, so
// a test can inspect exactly what the server wrote on each one.
type recordingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []*recordingConn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	rc := &recordingConn{Conn: c}
	l.mu.Lock()
	l.conns = append(l.conns, rc)
	l.mu.Unlock()
	return rc, nil
}

func (l *recordingListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

func (l *recordingListener) at(i int) *recordingConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns[i]
}

// stdlibSelfSigned builds a self-signed stdlib crypto/tls certificate for
// host, independent of this package's own utls-typed certFor/selfSigned
// (which serve CHIMERA's authorized-session path, not this test's vantage
// server).
func stdlibSelfSigned(t *testing.T, host string) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		IPAddresses:  []net.IP{net.ParseIP(host)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// runHeadlessChrome navigates chromePath to url and returns once the
// response has been received (or the timeout elapses). Chrome for Testing
// does not reliably self-exit after --dump-dom in this environment (it keeps
// background services, e.g. GCM registration, alive), so this polls the
// recorder for a connection instead of waiting on the process to exit, and
// force-kills the whole process tree afterward.
func runHeadlessChrome(t *testing.T, chromePath, url string, rln *recordingListener) {
	t.Helper()
	profile := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	args := []string{
		"--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
		"--ignore-certificate-errors", "--no-first-run", "--no-default-browser-check",
		"--disable-background-networking",
		"--user-data-dir=" + profile,
		url,
	}
	cmd := exec.CommandContext(ctx, chromePath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start chrome: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(30 * time.Second)
	for rln.count() == 0 && time.Now().Before(deadline) {
		select {
		case <-done:
			// Process exited (cleanly or not) before we observed a
			// connection; fall through to the post-loop check below.
			goto afterWait
		case <-time.After(200 * time.Millisecond):
		}
	}
afterWait:
	killProcessTree(cmd.Process.Pid)
	<-done // reap; error is expected once we kill it, so it is not checked

	if rln.count() == 0 {
		t.Fatalf("chrome never connected to %s; stderr:\n%s", url, stderr.String())
	}
}

func killProcessTree(pid int) {
	if pid <= 0 {
		return
	}
	// taskkill /T kills the whole tree (renderer/GPU/utility subprocesses);
	// os.Process.Kill only signals the top process, which headless Chrome's
	// child processes can outlive.
	_ = exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/T", "/F").Run()
}

// TestChromeVantageServerHelloParity is the real-Chrome ground-truth check
// described at the top of this file.
func TestChromeVantageServerHelloParity(t *testing.T) {
	chromePath := os.Getenv("CHIMERA_CHROME_PATH")
	if chromePath == "" {
		t.Skip("CHIMERA_CHROME_PATH not set; skipping real-Chrome vantage validation")
	}
	if _, err := os.Stat(chromePath); err != nil {
		t.Fatalf("CHIMERA_CHROME_PATH %q: %v", chromePath, err)
	}

	const host = "127.0.0.1"
	cert := stdlibSelfSigned(t, host)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	port := tcpLn.Addr().(*net.TCPAddr).Port
	stealHostAddr := net.JoinHostPort(host, fmt.Sprint(port))

	rln := &recordingListener{Listener: tcpLn}
	tlsLn := stdtls.NewListener(rln, &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS13,
		MaxVersion:   stdtls.VersionTLS13,
	})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("vantage"))
	})}
	srv.SetKeepAlivesEnabled(false)
	go func() { _ = srv.Serve(tlsLn) }()
	defer srv.Close()

	// --- ground truth: a real Chrome navigating to the vantage server ---
	runHeadlessChrome(t, chromePath, "https://"+stealHostAddr+"/", rln)
	chromeRaw, err := readServerHelloMessage(bytes.NewReader(rln.at(0).written()))
	if err != nil {
		t.Fatalf("extract real-Chrome ServerHello: %v", err)
	}
	shChrome, err := ParseServerHello(chromeRaw)
	if err != nil {
		t.Fatalf("parse real-Chrome ServerHello: %v", err)
	}
	t.Logf("real Chrome ServerHello: cipher=%#04x group=%#04x extensions=%v",
		shChrome.CipherSuite, shChrome.KeyShareGroup, extTypes(shChrome))

	// --- CHIMERA's own probe against the SAME vantage server ---
	dial := func() (net.Conn, error) { return net.Dial("tcp", stealHostAddr) }
	shOurs, err := ProbeServerHello(dial, host)
	if err != nil {
		t.Fatalf("ProbeServerHello: %v", err)
	}
	t.Logf("CHIMERA probe ServerHello: cipher=%#04x group=%#04x extensions=%v",
		shOurs.CipherSuite, shOurs.KeyShareGroup, extTypes(shOurs))

	if shOurs.CipherSuite != shChrome.CipherSuite {
		t.Errorf("probe cipher = %#04x, want real-Chrome ground truth %#04x", shOurs.CipherSuite, shChrome.CipherSuite)
	}
	if shOurs.KeyShareGroup != shChrome.KeyShareGroup {
		t.Errorf("probe group = %#04x, want real-Chrome ground truth %#04x", shOurs.KeyShareGroup, shChrome.KeyShareGroup)
	}
	if !reflect.DeepEqual(extTypes(shOurs), extTypes(shChrome)) {
		t.Errorf("probe extension order = %v, want real-Chrome ground truth %v", extTypes(shOurs), extTypes(shChrome))
	}

	// --- CHIMERA's authorized-session served ServerHello, end to end ---
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
		tc, err := ServerWrap(chimeraRec, prefix, ss, stealHostAddr) // probes the SAME vantage server internally
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
	t.Logf("CHIMERA-served ServerHello: cipher=%#04x group=%#04x extensions=%v",
		shChimera.CipherSuite, shChimera.KeyShareGroup, extTypes(shChimera))

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

func extTypes(t *ServerHelloTemplate) []uint16 {
	out := make([]uint16, len(t.Extensions))
	for i, e := range t.Extensions {
		out[i] = e.Type
	}
	return out
}
