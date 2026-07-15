package nethelper

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

type fakeRunner struct {
	running   bool
	startErr  error
	lastStart Request
	stats     TunnelStats
}

func (f *fakeRunner) Start(req Request) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.lastStart = req
	f.running = true
	return nil
}

func (f *fakeRunner) Stop() error {
	f.running = false
	return nil
}

func (f *fakeRunner) Running() bool { return f.running }

func (f *fakeRunner) Stats() TunnelStats { return f.stats }

func TestHandleRejectsBadToken(t *testing.T) {
	s := &Server{Token: "secret", Runner: &fakeRunner{}}
	resp := s.Handle(Request{Cmd: CmdPing, Token: "wrong"})
	if resp.OK {
		t.Fatalf("expected unauthorized, got OK response: %+v", resp)
	}
}

func TestHandleRejectsEmptyToken(t *testing.T) {
	s := &Server{Token: "", Runner: &fakeRunner{}}
	resp := s.Handle(Request{Cmd: CmdPing, Token: ""})
	if resp.OK {
		t.Fatalf("expected unauthorized when server has no token configured, got: %+v", resp)
	}
}

func TestHandlePingReportsState(t *testing.T) {
	r := &fakeRunner{running: true}
	s := &Server{Token: "secret", Runner: r}
	resp := s.Handle(Request{Cmd: CmdPing, Token: "secret"})
	if !resp.OK || resp.State != StateRunning {
		t.Fatalf("expected OK running, got: %+v", resp)
	}
}

func TestHandlePingReportsStats(t *testing.T) {
	r := &fakeRunner{running: true, stats: TunnelStats{BytesUp: 100, BytesDown: 200, Server: "s:443", Transport: "quic"}}
	s := &Server{Token: "secret", Runner: r}
	resp := s.Handle(Request{Cmd: CmdPing, Token: "secret"})
	if resp.BytesUp != 100 || resp.BytesDown != 200 || resp.Server != "s:443" || resp.Transport != "quic" {
		t.Fatalf("expected stats to be forwarded, got: %+v", resp)
	}
}

func TestHandlePingOmitsStatsWhenNotRunning(t *testing.T) {
	r := &fakeRunner{running: false, stats: TunnelStats{BytesUp: 100}}
	s := &Server{Token: "secret", Runner: r}
	resp := s.Handle(Request{Cmd: CmdPing, Token: "secret"})
	if resp.BytesUp != 0 {
		t.Fatalf("expected no stats when not running, got: %+v", resp)
	}
}

func TestHandleStartValidatesRequiredFields(t *testing.T) {
	s := &Server{Token: "secret", Runner: &fakeRunner{}}
	resp := s.Handle(Request{Cmd: CmdStart, Token: "secret", Pbk: "abc"})
	if resp.OK {
		t.Fatalf("expected error for missing server, got: %+v", resp)
	}
}

func TestHandleStartDispatchesToRunner(t *testing.T) {
	r := &fakeRunner{}
	s := &Server{Token: "secret", Runner: r}
	resp := s.Handle(Request{Cmd: CmdStart, Token: "secret", Server: "1.2.3.4:443", Pbk: "abc", Mode: ModeDNSLeakGuard})
	if !resp.OK || resp.State != StateRunning {
		t.Fatalf("expected OK running, got: %+v", resp)
	}
	if r.lastStart.Server != "1.2.3.4:443" || r.lastStart.Mode != ModeDNSLeakGuard {
		t.Fatalf("runner did not receive expected request: %+v", r.lastStart)
	}
}

func TestHandleStopAlwaysSucceeds(t *testing.T) {
	s := &Server{Token: "secret", Runner: &fakeRunner{}}
	resp := s.Handle(Request{Cmd: CmdStop, Token: "secret"})
	if !resp.OK || resp.State != StateIdle {
		t.Fatalf("expected OK idle, got: %+v", resp)
	}
}

func TestHandleUnknownCommand(t *testing.T) {
	s := &Server{Token: "secret", Runner: &fakeRunner{}}
	resp := s.Handle(Request{Cmd: "bogus", Token: "secret"})
	if resp.OK {
		t.Fatalf("expected error for unknown command, got: %+v", resp)
	}
}

func TestServeEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &fakeRunner{}
	s := &Server{Token: "secret", Runner: r}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if err := json.NewEncoder(conn).Encode(Request{Cmd: CmdStart, Token: "secret", Server: "s:443", Pbk: "p"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.State != StateRunning {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if !r.Running() {
		t.Fatalf("expected runner to be started")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}
