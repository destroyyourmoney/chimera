//go:build windows

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"chimera/internal/nethelper"
)

const serviceDisplayName = "CHIMERA Network Helper"
const serviceDescription = "Configures Windows network routing for the CHIMERA VPN tunnel. Only runs the tunnel setup a user explicitly requests from the CHIMERA tray app."

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own path: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("resolve absolute path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager (are you elevated?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {

		_ = s.Close()
	} else {
		s, err = m.CreateService(serviceName, exe, mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: serviceDisplayName,
			Description: serviceDescription,
		})
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		defer s.Close()

		if err := s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		}, 86400); err != nil {
			slog.Warn("chimera-helper install: set recovery actions", "err", err)
		}
	}

	tok, err := nethelper.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	if err := nethelper.WriteToken(tok); err != nil {
		return fmt.Errorf("write token: %w", err)
	}

	s, err = m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service after create: %w", err)
	}
	defer s.Close()

	if status, err := s.Query(); err == nil && status.State == svc.Running {

		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("restart service (stop): %w", err)
		}
		if err := waitForState(s, svc.Stopped, 10*time.Second); err != nil {
			return fmt.Errorf("restart service (wait stopped): %w", err)
		}
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	if err := waitForState(s, svc.Running, 10*time.Second); err != nil {
		return fmt.Errorf("wait for service to start: %w", err)
	}
	fmt.Println("chimera-helper: installed and running")
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager (are you elevated?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("chimera-helper: not installed")
			return nil
		}
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	if status, err := s.Query(); err == nil && status.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
		_ = waitForState(s, svc.Stopped, 10*time.Second)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	if path, err := nethelper.TokenPath(); err == nil {
		_ = os.Remove(path)
	}
	fmt.Println("chimera-helper: uninstalled")
	return nil
}

func printStatus() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Println("not installed")
		return nil
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	fmt.Println(stateName(status.State))
	return nil
}

func waitForState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for state %s", stateName(want))
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start pending"
	case svc.StopPending:
		return "stop pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue pending"
	case svc.PausePending:
		return "pause pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

func setupServiceLogging() {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		return
	}
	dir = filepath.Join(dir, "chimera")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "helper-service.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
}
