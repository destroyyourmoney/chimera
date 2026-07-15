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

// procRunner is nethelper.Runner backed by a chimera.exe tun child process.
// The service that owns a procRunner runs as LocalSystem, so spawning that
// child inherits SYSTEM's token directly -- no UAC, no re-elevation dance --
// which is the entire reason this service exists (see main.go's doc
// comment). Start/Stop reuse chimera.exe's existing, already-tested
// `tun -setup-os/-setup-firewall/-setup-killswitch/-setup-restore` flags
// (internal/winnet) instead of reimplementing any of that logic here.
type procRunner struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{} // closed once cmd.Wait() returns; guards against double-Wait
}

// chimeraExePath resolves chimera.exe as a sibling of the running
// chimera-helper.exe -- both are installed into the same app directory by
// scripts/build-app-windows.ps1.
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

	// A new Start while one is already running is a "switch server/mode"
	// request: stop the old tunnel first rather than leaving two fighting
	// over the same TUN device name.
	r.stopLocked()

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
		// Clear tracked state once the process is actually gone, but only if
		// nothing else (a subsequent Start/Stop) has already replaced it --
		// otherwise Running() would report true forever for a child that
		// crashed or was killed, which is exactly the bug this fixes: the
		// service kept telling callers "running" after chimera.exe tun had
		// already exited.
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

	// Give the process a moment to fail fast (missing wintun.dll, bad
	// server/pbk rejected by the CLI's own flag validation, etc.) so Start
	// can report a real error instead of "ok" for a tunnel that was already
	// dead by the time the caller's next ping arrived.
	select {
	case err := <-waitErr:
		// The exit-tracking goroutine will also try to clear r.cmd/r.done
		// once it gets r.mu (which we're still holding here) -- clearing
		// them here too makes the failure immediate and deterministic
		// rather than depending on that goroutine winning a lock race.
		r.cmd = nil
		r.done = nil
		return fmt.Errorf("chimera-helper: chimera.exe tun exited immediately (see %s): %w", logPath, err)
	case <-time.After(500 * time.Millisecond):
	}

	slog.Info("chimera-helper: tunnel started", "pid", cmd.Process.Pid, "mode", req.Mode, "server", req.Server)
	return nil
}

func (r *procRunner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()

	// stopLocked kills the child rather than cancelling its context, so it
	// never reaches its own final "idle" write in runStatusWriter -- remove
	// the file directly so Stats()/state() don't keep reporting a stale
	// "running" tunnel with frozen byte counts after Stop.
	if err := os.Remove(statusFilePath()); err != nil && !os.IsNotExist(err) {
		slog.Warn("chimera-helper: remove stale status file", "err", err)
	}

	// Unconditional cleanup pass regardless of whether a tracked process was
	// running: guarantees routes/DNS/firewall are restored even after a
	// service restart lost track of a previous run, or the child died
	// without us noticing. Restore errors (e.g. the TUN adapter is already
	// gone) are logged, not surfaced -- see nethelper.Server.Handle's doc
	// comment on why Stop is best-effort from the caller's perspective.
	exe, err := chimeraExePath()
	if err != nil {
		slog.Warn("chimera-helper: restore skipped, could not resolve chimera.exe", "err", err)
		return nil
	}
	out, err := exec.Command(exe, "tun", "-setup-restore").CombinedOutput()
	if err != nil {
		slog.Warn("chimera-helper: restore reported an error (often harmless, e.g. nothing to restore)", "err", err, "output", string(out))
	}
	return nil
}

// stopLocked kills the tracked child, if any, and waits for its Wait()
// goroutine to finish so a subsequent Start doesn't race with it. Caller
// must hold r.mu.
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

// tunStatus mirrors cmd/chimera/tun_on.go's tunStatus -- kept as a separate
// definition since the two are different binaries/packages, same JSON shape
// by convention (see -status-file's doc comment on both sides).
type tunStatus struct {
	State     string `json:"state"`
	BytesUp   uint64 `json:"bytesUp"`
	BytesDown uint64 `json:"bytesDown"`
	Server    string `json:"server"`
	Transport string `json:"transport"`
	UpdatedAt int64  `json:"updatedAt"`
}

// Stats reads the status file the running chimera.exe tun child writes to
// (see statusFilePath, and this Runner's Start passing -status-file).
// Best-effort: missing/stale/unparseable -> zero value, never an error --
// stats are a nice-to-have display, not something a caller should have to
// handle failing.
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

// statusFilePath: %ProgramData%, same rationale as helperLogPath (the
// service runs as LocalSystem).
func statusFilePath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		return filepath.Join(os.TempDir(), "chimera-helper-tunnel-status.json")
	}
	return filepath.Join(dir, "chimera", "tunnel-status.json")
}

// helperLogPath: %ProgramData%, not %LocalAppData% -- the service runs as
// LocalSystem, which has its own profile distinct from any logged-in user's
// (see token.go's doc comment for the same issue with the auth token).
func helperLogPath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		return filepath.Join(os.TempDir(), "chimera-helper-tunnel.log")
	}
	return filepath.Join(dir, "chimera", "helper-tunnel.log")
}
