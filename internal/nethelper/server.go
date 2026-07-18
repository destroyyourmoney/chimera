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

type Runner interface {
	Start(req Request) error

	Stop() error

	Running() bool

	Stats() TunnelStats
}

type Server struct {
	Token  string
	Runner Runner
}

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

		_ = s.Runner.Stop()
		return Response{OK: true, State: StateIdle}
	default:
		return Response{OK: false, Error: fmt.Sprintf("unknown command %q", req.Cmd)}
	}
}

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
