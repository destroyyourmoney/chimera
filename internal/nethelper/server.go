package nethelper

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
)

// Runner starts and stops the actual elevated tunnel process (chimera.exe
// tun, in cmd/chimera-helper's real implementation). Kept as an interface so
// Server's request-dispatch logic (auth, validation, command routing) is
// unit-testable without a real Windows service or admin rights.
type Runner interface {
	// Start launches (or restarts, if already running) the tunnel described
	// by req. req.Cmd/req.Token have already been validated by Server.
	Start(req Request) error
	// Stop tears down any running tunnel. Idempotent: called with nothing
	// running is not an error.
	Stop() error
	// Running reports whether a tunnel is currently up.
	Running() bool
	// Stats returns the current tunnel's live throughput/identity snapshot.
	// Zero-value when nothing is running or stats aren't available yet.
	Stats() TunnelStats
}

// Server dispatches validated Requests to a Runner. Token must match
// Request.Token (constant-time) or every command is rejected as
// unauthorized, including ping -- an unauthenticated caller learns nothing.
type Server struct {
	Token  string
	Runner Runner
}

// Handle validates and dispatches a single request. Exported (rather than
// folded into the accept loop) so tests can drive it directly.
func (s *Server) Handle(req Request) Response {
	if s.Token == "" || subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.Token)) != 1 {
		return Response{OK: false, Error: "unauthorized"}
	}
	switch req.Cmd {
	case CmdPing:
		resp := Response{OK: true, State: s.state()}
		if s.Runner.Running() {
			s.fillStats(&resp)
		}
		return resp
	case CmdStart:
		if req.Server == "" || req.Pbk == "" {
			return Response{OK: false, Error: "server and pbk are required"}
		}
		if err := s.Runner.Start(req); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		resp := Response{OK: true, State: StateRunning}
		s.fillStats(&resp)
		return resp
	case CmdStop:
		// Stop is intentionally best-effort from the caller's perspective:
		// "make sure nothing is tunneled/routed anymore" always succeeds as
		// far as the client is concerned, even if the underlying cleanup
		// script errored (e.g. the TUN adapter was already gone) -- the
		// Runner logs that detail itself; see cmd/chimera-helper's Runner.
		_ = s.Runner.Stop()
		return Response{OK: true, State: StateIdle}
	default:
		return Response{OK: false, Error: fmt.Sprintf("unknown command %q", req.Cmd)}
	}
}

// fillStats copies the Runner's current stats into resp.
func (s *Server) fillStats(resp *Response) {
	stats := s.Runner.Stats()
	resp.BytesUp = stats.BytesUp
	resp.BytesDown = stats.BytesDown
	resp.Server = stats.Server
	resp.Transport = stats.Transport
}

func (s *Server) state() string {
	if s.Runner.Running() {
		return StateRunning
	}
	return StateIdle
}

// Serve accepts connections on ln until ctx is cancelled or ln closes,
// handling exactly one Request per connection (see package doc: this is a
// request/response protocol, not a persistent session).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("nethelper: accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	var req Request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		slog.Warn("nethelper: malformed request", "remote", conn.RemoteAddr(), "err", err)
		return
	}
	resp := s.Handle(req)
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		slog.Warn("nethelper: write response", "remote", conn.RemoteAddr(), "err", err)
	}
}
