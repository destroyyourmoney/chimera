//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"chimera/internal/nethelper"
)

type procRunner struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}

	lastServer string
}

func chimeraExePath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("chimera-helper: resolve own path: %w", err)
	}
	return filepath.Join(filepath.Dir(self), "chimera.exe"), nil
}

func (r *procRunner) Start(req nethelper.Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	wasRunning := r.cmd != nil
	prevServer := r.lastServer
	r.stopLocked()
	if wasRunning {
		r.restoreLocked(prevServer)
	}
	r.lastServer = req.Server

	exe, err := chimeraExePath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("chimera-helper: chimera.exe not found next to the helper: %w", err)
	}

	args := []string{"tun", "-v", "-setup-os", "-setup-firewall"}
	if req.Mode == nethelper.ModeKillswitch {
		args = append(args, "-setup-killswitch")
	}
	args = append(args, "-setup-keep", "-server", req.Server, "-pbk", req.Pbk)
	if req.Sni != "" {
		args = append(args, "-sni", req.Sni)
	}
	if req.Sid != "" {
		args = append(args, "-sid", req.Sid)
	}
	if len(req.DNS) > 0 {
		args = append(args, "-dns", strings.Join(req.DNS, ","))
	}
	if req.Transport != "" {
		args = append(args, "-transport", req.Transport)
	}
	if req.CapabilityToken != "" {
		args = append(args, "-token", req.CapabilityToken)
	}
	args = append(args, "-status-file", statusFilePath())

	cmd := exec.Command(exe, args...)
	logPath := helperLogPath()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		slog.Warn("chimera-helper: could not create tunnel log dir", "err", err)
	}
	if f, err := os.Create(logPath); err == nil {
		cmd.Stdout = f
		cmd.Stderr = f
	} else {
		slog.Warn("chimera-helper: could not open tunnel log", "path", logPath, "err", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("chimera-helper: start chimera.exe tun: %w", err)
	}

	r.cmd = cmd
	done := make(chan struct{})
	r.done = done
	waitErr := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		waitErr <- err
		close(done)

		r.mu.Lock()
		if r.cmd == cmd {
			r.cmd = nil
			r.done = nil
		}
		r.mu.Unlock()
		if err != nil {
			slog.Warn("chimera-helper: tunnel process exited", "pid", cmd.Process.Pid, "err", err)
		} else {
			slog.Info("chimera-helper: tunnel process exited cleanly", "pid", cmd.Process.Pid)
		}
	}()

	select {
	case err := <-waitErr:

		r.cmd = nil
		r.done = nil
		return fmt.Errorf("chimera-helper: chimera.exe tun exited immediately (see %s): %w", logPath, err)
	case <-time.After(500 * time.Millisecond):
	}

	slog.Info("chimera-helper: tunnel started", "pid", cmd.Process.Pid, "mode", req.Mode)
	return nil
}

func (r *procRunner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()

	if err := os.Remove(statusFilePath()); err != nil && !os.IsNotExist(err) {
		slog.Warn("chimera-helper: remove stale status file", "err", err)
	}

	r.restoreLocked(r.lastServer)
	return nil
}

func (r *procRunner) restoreLocked(server string) {
	exe, err := chimeraExePath()
	if err != nil {
		slog.Warn("chimera-helper: restore skipped, could not resolve chimera.exe", "err", err)
		return
	}
	restoreArgs := []string{"tun", "-setup-restore"}
	if server != "" {

		restoreArgs = append(restoreArgs, "-server", server)
	}
	out, err := exec.Command(exe, restoreArgs...).CombinedOutput()
	if err != nil {
		slog.Warn("chimera-helper: restore reported an error (often harmless, e.g. nothing to restore)", "err", err, "output", string(out))
	}
}

func (r *procRunner) stopLocked() {
	if r.cmd == nil || r.cmd.Process == nil {
		return
	}
	pid := r.cmd.Process.Pid
	if err := r.cmd.Process.Kill(); err != nil {
		slog.Warn("chimera-helper: kill tunnel process", "pid", pid, "err", err)
	}
	<-r.done
	slog.Info("chimera-helper: tunnel process stopped", "pid", pid)
	r.cmd = nil
	r.done = nil
}

func (r *procRunner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

type tunStatus struct {
	State     string `json:"state"`
	BytesUp   uint64 `json:"bytesUp"`
	BytesDown uint64 `json:"bytesDown"`
	Server    string `json:"server"`
	Transport string `json:"transport"`
	UpdatedAt int64  `json:"updatedAt"`
}

func (r *procRunner) Stats() nethelper.TunnelStats {
	data, err := os.ReadFile(statusFilePath())
	if err != nil {
		return nethelper.TunnelStats{}
	}
	var st tunStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return nethelper.TunnelStats{}
	}
	return nethelper.TunnelStats{
		BytesUp:   st.BytesUp,
		BytesDown: st.BytesDown,
		Server:    st.Server,
		Transport: st.Transport,
	}
}

func statusFilePath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		return filepath.Join(os.TempDir(), "chimera-helper-tunnel-status.json")
	}
	return filepath.Join(dir, "chimera", "tunnel-status.json")
}

func helperLogPath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		return filepath.Join(os.TempDir(), "chimera-helper-tunnel.log")
	}
	return filepath.Join(dir, "chimera", "helper-tunnel.log")
}
