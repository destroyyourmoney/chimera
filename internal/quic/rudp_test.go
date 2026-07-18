//go:build chimera_quic

package quic

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"chimera/internal/carrier"
	"chimera/internal/rudp"
)

func dialLoopbackQUIC(t *testing.T) (client, server *quic.Conn) {
	t.Helper()
	tlsConf, err := serverTLS()
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, quicConfig(0))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srvCh := make(chan *quic.Conn, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err == nil {
			srvCh <- conn
		}
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
		MinVersion:         tls.VersionTLS13,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err = quic.DialAddr(ctx, ln.Addr().String(), clientTLS, quicConfig(0))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server = <-srvCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server accept timed out")
	}
	return client, server
}

func TestRUDPOverQUICDatagrams(t *testing.T) {
	clientConn, serverConn := dialLoopbackQUIC(t)
	defer clientConn.CloseWithError(0, "")
	defer serverConn.CloseWithError(0, "")

	cfg := rudp.Config{MSS: 1000, FEC: true}
	sender := rudp.NewConn(newQUICDatagram(clientConn), cfg)
	receiver := rudp.NewConn(newQUICDatagram(serverConn), cfg)

	payload := make([]byte, 512<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var (
		got     []byte
		readErr error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = receiver.SetReadDeadline(time.Now().Add(30 * time.Second))
		got, readErr = io.ReadAll(receiver)
	}()

	if _, err := sender.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sender.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	wg.Wait()
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if len(got) != len(payload) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(payload))
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("payload not byte-exact over QUIC datagrams")
	}
	_ = receiver.Close()
	t.Logf("rudp-over-QUIC byte-exact: %d bytes, sender stats %+v", len(got), sender.Stats())
}

func TestRUDPCarrierConnectRelay(t *testing.T) {
	addr, pub := startServer(t)
	echoHost, echoPort := startEcho(t)
	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: "example.com", Transport: "quic-rudp"}

	conn, err := carrier.DialConnect(cfg, echoHost, echoPort)
	if err != nil {
		t.Fatalf("dial quic-rudp connect: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 2<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	got := make([]byte, len(payload))
	var (
		readErr error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, readErr = io.ReadFull(conn, got)
	}()

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	wg.Wait()
	if readErr != nil {
		t.Fatalf("read echo: %v", readErr)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("echo not byte-exact over quic-rudp carrier")
	}
	t.Logf("quic-rudp carrier echo byte-exact: %d bytes", len(got))
}
