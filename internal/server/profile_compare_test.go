//go:build chimera_utls

package server_test

// This file closes the last unmeasured Этап 2 MVP acceptance criterion
// (ROADMAP.md "Профиль сессии близок к прямому HTTPS на steal-host; вложенный
// CH не виден" -- "session profile close to direct HTTPS to the steal-host;
// nested ClientHello not visible"). Until now that line was only a logical
// inference from the architecture (authorized session = real TLS 1.3
// terminated by internal/reality.ServerWrap); it had never actually been
// measured on the wire.
//
// What this test does, concretely:
//
//  1. Stands up a REAL TLS 1.3 steal-host stand-in (crypto/tls.Listen, a
//     self-signed cert, a tiny fixed HTTP/1.1 response) -- not the plaintext
//     fakeSteal used by the rest of this package's tests.
//  2. Runs the real CHIMERA server (server.Serve, chimera_utls build so the
//     authorized path takes internal/reality.ServerWrap -- a genuine TLS 1.3
//     handshake) pointed at that steal-host.
//  3. Flow A ("chimera"): a real carrier client authenticates, then issues
//     CmdConnect back to the SAME steal-host address. Over the resulting
//     tunnel it runs a SECOND, independent TLS 1.3 handshake (crypto/tls)
//     straight through to the steal-host and does a small HTTP GET/response
//     exchange -- i.e. this deliberately performs a nested ClientHello
//     (TLS-in-TLS), the exact scenario Этап 2's title ("защита от
//     TLS-in-TLS") worries about, so the capture can prove whether it is
//     visible on the wire or not.
//  4. Flow B ("direct"): a plain crypto/tls.Dial straight to the same
//     steal-host stand-in, same GET/response exchange, no CHIMERA involved.
//  5. Both flows are captured at the wire (raw bytes + timestamps, both
//     directions) at the same vantage point: the TCP hop between the client
//     and whatever entity occupies the "steal-host" position on that wire
//     (the relay's far-side connection to the real CHIMERA server for Flow
//     A, or the client's direct TCP connection for Flow B -- see
//     TestSessionStartupByteCount above for the same relay-capture
//     technique this reuses).
//  6. The capture is parsed at the TLS record layer (record headers are
//     never encrypted) to get record-type sequence/sizes, Shannon entropy of
//     application-data payloads, and inter-write timing -- and to positively
//     check for the literal ClientHello byte-signature
//     (0x16 0x03 [0-3] .. 0x01 at offset 5, i.e. vision.Classify's own
//     detector) anywhere in the stream past the legitimate outer handshake.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"chimera/internal/carrier"
	"chimera/internal/keys"
)

// ---- steal-host stand-in: a REAL TLS 1.3 server, not the plaintext fakeSteal ----

const stealHTTPBody = "<html><body>chimera-profile-compare steal-host stand-in</body></html>"

func stealHTTPResponse() []byte {
	body := stealHTTPBody
	return []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body))
}

// selfSignedTLSCert builds a minimal self-signed TLS 1.3 certificate for host,
// good enough for crypto/tls.Listen (client side dials with InsecureSkipVerify,
// same posture as the real steal-host stand-ins elsewhere in this codebase).
func selfSignedTLSCert(t *testing.T, host string) tls.Certificate {
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// realTLSStealHost stands up a genuine TLS 1.3 HTTPS server: real ServerHello,
// real Finished, a small fixed HTTP/1.1 response. This is the ground truth
// both flows below are measured against.
func realTLSStealHost(t *testing.T) (addr string, stop func()) {
	t.Helper()
	cert := selfSignedTLSCert(t, "127.0.0.1")
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("steal-host listen: %v", err)
	}
	tlsLn := tls.NewListener(tcpLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				// Read (and discard) the request line + headers up to the blank line.
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				_, _ = c.Write(stealHTTPResponse())
			}(c)
		}
	}()
	return tcpLn.Addr().String(), func() { _ = tlsLn.Close() }
}

// ---- wire capture: raw bytes + timestamps, both directions ----

type wireEvent struct {
	t    time.Time
	dir  byte // 'W' = client -> wire (tx), 'R' = wire -> client (rx)
	size int
}

type wireCapture struct {
	mu       sync.Mutex
	events   []wireEvent
	txStream []byte
	rxStream []byte
}

func (w *wireCapture) record(dir byte, p []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, wireEvent{t: time.Now(), dir: dir, size: len(p)})
	if dir == 'W' {
		w.txStream = append(w.txStream, p...)
	} else {
		w.rxStream = append(w.rxStream, p...)
	}
}

// capturingConn wraps a net.Conn, logging every Read/Write with a timestamp
// and a copy of the bytes, so the exact wire content and cadence can be
// reconstructed after the fact.
type capturingConn struct {
	net.Conn
	cap *wireCapture
}

func (c *capturingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.cap.record('R', p[:n])
	}
	return n, err
}

func (c *capturingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.cap.record('W', p[:n])
	}
	return n, err
}

// ---- TLS record-layer parsing (headers are never encrypted) ----

type tlsRecord struct {
	typ    byte
	ver    uint16
	length int
}

func parseRecords(stream []byte) []tlsRecord {
	var out []tlsRecord
	i := 0
	for i+5 <= len(stream) {
		typ := stream[i]
		ver := uint16(stream[i+1])<<8 | uint16(stream[i+2])
		length := int(stream[i+3])<<8 | int(stream[i+4])
		if i+5+length > len(stream) {
			break // incomplete trailing record (capture ended mid-record)
		}
		out = append(out, tlsRecord{typ, ver, length})
		i += 5 + length
	}
	return out
}

// appDataPayloads returns the concatenation of every type-0x17 (application
// data) record body in stream. At the TLS 1.3 record layer this covers both
// the encrypted post-ServerHello handshake messages (EncryptedExtensions,
// Certificate, CertificateVerify, Finished -- all opaque-typed 0x17 on the
// wire per RFC 8446) and true post-handshake application data: all of it is
// AEAD ciphertext and should be statistically indistinguishable from random.
func appDataPayloads(stream []byte) []byte {
	var out []byte
	i := 0
	for i+5 <= len(stream) {
		typ := stream[i]
		length := int(stream[i+3])<<8 | int(stream[i+4])
		if i+5+length > len(stream) {
			break
		}
		if typ == 0x17 {
			out = append(out, stream[i+5:i+5+length]...)
		}
		i += 5 + length
	}
	return out
}

// shannonEntropy returns the Shannon entropy of b in bits/byte (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	total := float64(len(b))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / total
		h -= p * math.Log2(p)
	}
	return h
}

// clientHelloSigMatches reports offsets where stream matches the exact
// heuristic internal/vision.Classify uses to detect an embedded ClientHello:
// content-type 0x16, legacy_record_version 0x0301-0x0303, handshake_type
// 0x01 (ClientHello) at byte offset 5 relative to the match start.
func clientHelloSigMatches(stream []byte) []int {
	var hits []int
	for i := 0; i+6 <= len(stream); i++ {
		if stream[i] == 0x16 && stream[i+1] == 0x03 && stream[i+2] <= 0x03 && stream[i+5] == 0x01 {
			hits = append(hits, i)
		}
	}
	return hits
}

// nonHandshakeTail reports whether, once the record stream moves past the
// initial plaintext-typed handshake/CCS records (0x16, 0x14), any further
// 0x16-typed (Handshake) record appears. A real second cleartext handshake
// spliced onto the wire -- as opposed to one safely wrapped as ciphertext
// inside outer application-data records -- would show up here.
func recordTypeSeq(recs []tlsRecord) []byte {
	seq := make([]byte, len(recs))
	for i, r := range recs {
		seq[i] = r.typ
	}
	return seq
}

func handshakeRecordsAfterFirstAppData(recs []tlsRecord) int {
	seenAppData := false
	n := 0
	for _, r := range recs {
		if r.typ == 0x17 {
			seenAppData = true
			continue
		}
		if seenAppData && r.typ == 0x16 {
			n++
		}
	}
	return n
}

// ---- flow runner: performs one HTTP GET/response exchange over conn, whose
// wire bytes are ALREADY being captured by capturingConn underneath ----

func doHTTPSExchange(t *testing.T, conn net.Conn, host string) {
	t.Helper()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake to steal-host: %v", err)
	}
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := io.ReadAll(tlsConn)
	if err != nil && err != io.EOF {
		t.Fatalf("read response: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response from steal-host")
	}
}

// profileStats summarizes one flow's captured wire bytes for reporting.
type profileStats struct {
	name         string
	txBytes      int
	rxBytes      int
	txWrites     []int
	rxReads      []int
	txRecordSeq  []byte
	rxRecordSeq  []byte
	entropy      float64 // Shannon entropy (bits/byte) of app-data payloads, both directions
	nestedCHHits int      // literal ClientHello-signature matches past offset 0 in tx
	badHandshake int      // 0x16 records after app-data has begun (tx+rx)
	gapsMs       []float64
}

func summarize(name string, w *wireCapture) profileStats {
	w.mu.Lock()
	defer w.mu.Unlock()

	txRecs := parseRecords(w.txStream)
	rxRecs := parseRecords(w.rxStream)

	appData := append(append([]byte(nil), appDataPayloads(w.txStream)...), appDataPayloads(w.rxStream)...)

	// Nested-ClientHello signature check: the legitimate outer ClientHello is
	// expected at tx offset 0. Anything else, anywhere in tx or rx, is a hit.
	hits := 0
	for _, off := range clientHelloSigMatches(w.txStream) {
		if off != 0 {
			hits++
		}
	}
	hits += len(clientHelloSigMatches(w.rxStream)) // rx never legitimately starts with a ClientHello

	bad := handshakeRecordsAfterFirstAppData(txRecs) + handshakeRecordsAfterFirstAppData(rxRecs)

	sorted := append([]wireEvent(nil), w.events...)
	// events already appended in call order per connection; merge is already
	// chronological since both directions share the same wall clock.
	var gaps []float64
	for i := 1; i < len(sorted); i++ {
		gaps = append(gaps, sorted[i].t.Sub(sorted[i-1].t).Seconds()*1000)
	}

	var txSizes, rxSizes []int
	for _, e := range sorted {
		if e.dir == 'W' {
			txSizes = append(txSizes, e.size)
		} else {
			rxSizes = append(rxSizes, e.size)
		}
	}

	return profileStats{
		name:         name,
		txBytes:      len(w.txStream),
		rxBytes:      len(w.rxStream),
		txWrites:     txSizes,
		rxReads:      rxSizes,
		txRecordSeq:  recordTypeSeq(txRecs),
		rxRecordSeq:  recordTypeSeq(rxRecs),
		entropy:      shannonEntropy(appData),
		nestedCHHits: hits,
		badHandshake: bad,
		gapsMs:       gaps,
	}
}

func (s profileStats) log(t *testing.T) {
	t.Helper()
	t.Logf("[%s] tx=%dB rx=%dB total=%dB", s.name, s.txBytes, s.rxBytes, s.txBytes+s.rxBytes)
	t.Logf("[%s] tx writes (n=%d): %v", s.name, len(s.txWrites), s.txWrites)
	t.Logf("[%s] rx reads  (n=%d): %v", s.name, len(s.rxReads), s.rxReads)
	t.Logf("[%s] tx record types: %v", s.name, s.txRecordSeq)
	t.Logf("[%s] rx record types: %v", s.name, s.rxRecordSeq)
	t.Logf("[%s] app-data entropy: %.4f bits/byte", s.name, s.entropy)
	t.Logf("[%s] nested-ClientHello signature hits (excl. legit offset 0): %d", s.name, s.nestedCHHits)
	t.Logf("[%s] handshake(0x16) records after app-data began: %d", s.name, s.badHandshake)
	if len(s.gapsMs) > 0 {
		var sum, max float64
		for _, g := range s.gapsMs {
			sum += g
			if g > max {
				max = g
			}
		}
		t.Logf("[%s] inter-event gaps: n=%d mean=%.3fms max=%.3fms", s.name, len(s.gapsMs), sum/float64(len(s.gapsMs)), max)
	}
}

// TestSessionProfileVsDirectHTTPS is the real measurement behind ROADMAP.md's
// Этап 2 acceptance line "Профиль сессии близок к прямому HTTPS на
// steal-host; вложенный CH не виден". See the file-level doc comment above
// for the full methodology.
func TestSessionProfileVsDirectHTTPS(t *testing.T) {
	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	stealAddr, stopSteal := realTLSStealHost(t)
	defer stopSteal()
	stealHost, stealPortStr, err := net.SplitHostPort(stealAddr)
	if err != nil {
		t.Fatal(err)
	}
	var stealPort uint16
	if _, err := fmt.Sscanf(stealPortStr, "%d", &stealPort); err != nil {
		t.Fatal(err)
	}

	srvAddr := startServer(t, priv, "aabbccdd", stealAddr)

	// ---- Flow A: CHIMERA authorized session, CONNECT back to the steal-host,
	// then a real (nested) TLS handshake + HTTP GET over the tunnel ----
	chimeraCap := &wireCapture{}
	{
		serverConn, err := net.DialTimeout("tcp", srvAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial real server: %v", err)
		}
		counted := &capturingConn{Conn: serverConn, cap: chimeraCap}

		relayLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("relay listen: %v", err)
		}
		defer relayLn.Close()
		go func() {
			c, err := relayLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			defer counted.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(counted, c); done <- struct{}{} }()
			go func() { io.Copy(c, counted); done <- struct{}{} }()
			<-done
		}()

		cfg := carrier.Config{Server: relayLn.Addr().String(), PubB64: pub, SNI: "example.com", ShortIDHex: "aabbccdd"}
		conn, err := carrier.DialConnect(cfg, stealHost, stealPort)
		if err != nil {
			t.Fatalf("carrier CONNECT to steal-host: %v", err)
		}
		defer conn.Close()
		doHTTPSExchange(t, conn, stealHost)
		// Give the relay goroutines a moment to flush the tail of the capture.
		time.Sleep(50 * time.Millisecond)
	}

	// ---- Flow B: direct TLS straight to the same steal-host, no CHIMERA ----
	directCap := &wireCapture{}
	{
		raw, err := net.DialTimeout("tcp", stealAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial steal-host directly: %v", err)
		}
		counted := &capturingConn{Conn: raw, cap: directCap}
		doHTTPSExchange(t, counted, stealHost)
		counted.Close()
	}

	chimeraStats := summarize("chimera", chimeraCap)
	directStats := summarize("direct", directCap)
	chimeraStats.log(t)
	directStats.log(t)

	byteDelta := (chimeraStats.txBytes + chimeraStats.rxBytes) - (directStats.txBytes + directStats.rxBytes)
	entropyDelta := chimeraStats.entropy - directStats.entropy
	t.Logf("delta: total_bytes=%+d entropy=%+.4f bits/byte", byteDelta, entropyDelta)

	// --- correctness checks ---

	// 1. No literal embedded-ClientHello signature anywhere it shouldn't be.
	if chimeraStats.nestedCHHits != 0 {
		t.Errorf("CHIMERA flow: found %d ClientHello-signature matches outside the legitimate outer handshake -- "+
			"nested ClientHello IS visible on the wire (claim does NOT hold)", chimeraStats.nestedCHHits)
	}
	if directStats.nestedCHHits != 0 {
		t.Errorf("direct flow: unexpected ClientHello-signature matches (%d) -- baseline itself is suspect", directStats.nestedCHHits)
	}

	// 2. No cleartext-typed (0x16) handshake record ever appears after the
	// record stream has moved into application-data territory, in either
	// direction, for the CHIMERA flow: the inner (nested) TLS handshake to
	// the steal-host must be fully wrapped as opaque outer application data,
	// never spliced onto the wire as its own top-level TLS record.
	if chimeraStats.badHandshake != 0 {
		t.Errorf("CHIMERA flow: %d handshake(0x16) records appeared after application data began -- "+
			"the inner handshake is leaking as its own top-level TLS record, not hidden inside outer ciphertext",
			chimeraStats.badHandshake)
	}

	// 3. Application-data payload entropy must look like ciphertext (close to
	// the 8 bits/byte maximum for a byte alphabet), for both flows -- this is
	// the quantitative form of "no discernible structure" for a passive DPI
	// looking at entropy alone.
	const minEntropy = 7.5
	if chimeraStats.entropy < minEntropy {
		t.Errorf("CHIMERA flow app-data entropy = %.4f bits/byte, want >= %.2f (ciphertext-like)", chimeraStats.entropy, minEntropy)
	}
	if directStats.entropy < minEntropy {
		t.Errorf("direct flow app-data entropy = %.4f bits/byte, want >= %.2f (ciphertext-like)", directStats.entropy, minEntropy)
	}
}
