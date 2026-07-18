//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sys/windows/svc"

	"chimera/internal/nethelper"
)

const serviceName = "ChimeraNetHelper"

type chimeraService struct {
	server *nethelper.Server
}

func (s *chimeraService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	addr := fmt.Sprintf("127.0.0.1:%d", nethelper.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("chimera-helper: listen failed", "addr", addr, "err", err)
		status <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.server.Serve(ctx, ln) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	slog.Info("chimera-helper: service running", "listen", addr)

loop:
	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				break loop
			}
		case err := <-serveDone:
			if err != nil {
				slog.Error("chimera-helper: serve loop exited unexpectedly", "err", err)
			}
			break loop
		}
	}

	cancel()
	_ = s.server.Runner.Stop()
	status <- svc.Status{State: svc.Stopped}
	return false, 0
}
