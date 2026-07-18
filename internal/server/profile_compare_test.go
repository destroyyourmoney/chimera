//go:build chimera_utls

package server_test

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

const stealHTTPBody = "<html><body>chimera-profile-compare steal-host stand-in</body></html>"

func stealHTTPResponse() []byte {
	body := stealHTTPBody
	return []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body))
}

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

type wireEvent struct {
	t    time.Time
	dir  byte
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
			break
		}
		out = append(out, tlsRecord{typ, ver, length})
		i += 5 + length
	}
	return out
}

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

func clientHelloSigMatches(stream []byte) []int {
	var hits []int
	for i := 0; i+6 <= len(stream); i++ {
		if stream[i] == 0x16 && stream[i+1] == 0x03 && stream[i+2] <= 0x03 && stream[i+5] == 0x01 {
			hits = append(hits, i)
		}
	}
	return hits
}

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

type profileStats struct {
	name         string
	txBytes      int
	rxBytes      int
	txWrites     []int
	rxReads      []int
	txRecordSeq  []byte
	rxRecordSeq  []byte
	entropy      float64
	nestedCHHits int
	badHandshake int
	gapsMs       []float64
}

func summarize(name string, w *wireCapture) profileStats {
	w.mu.Lock()
	defer w.mu.Unlock()

	txRecs := parseRecords(w.txStream)
	rxRecs := parseRecords(w.rxStream)

	appData := append(append([]byte(nil), appDataPayloads(w.txStream)...), appDataPayloads(w.rxStream)...)

	hits := 0
	for _, off := range clientHelloSigMatches(w.txStream) {
		if off != 0 {
			hits++
		}
	}
	hits += len(clientHelloSigMatches(w.rxStream))

	bad := handshakeRecordsAfterFirstAppData(txRecs) + handshakeRecordsAfterFirstAppData(rxRecs)

	sorted := append([]wireEvent(nil), w.events...)

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

		time.Sleep(50 * time.Millisecond)
	}

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

	if chimeraStats.nestedCHHits != 0 {
		t.Errorf("CHIMERA flow: found %d ClientHello-signature matches outside the legitimate outer handshake -- "+
			"nested ClientHello IS visible on the wire (claim does NOT hold)", chimeraStats.nestedCHHits)
	}
	if directStats.nestedCHHits != 0 {
		t.Errorf("direct flow: unexpected ClientHello-signature matches (%d) -- baseline itself is suspect", directStats.nestedCHHits)
	}

	if chimeraStats.badHandshake != 0 {
		t.Errorf("CHIMERA flow: %d handshake(0x16) records appeared after application data began -- "+
			"the inner handshake is leaking as its own top-level TLS record, not hidden inside outer ciphertext",
			chimeraStats.badHandshake)
	}

	const minEntropy = 7.5
	if chimeraStats.entropy < minEntropy {
		t.Errorf("CHIMERA flow app-data entropy = %.4f bits/byte, want >= %.2f (ciphertext-like)", chimeraStats.entropy, minEntropy)
	}
	if directStats.entropy < minEntropy {
		t.Errorf("direct flow app-data entropy = %.4f bits/byte, want >= %.2f (ciphertext-like)", directStats.entropy, minEntropy)
	}
}
