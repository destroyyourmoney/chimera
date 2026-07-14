//go:build windows

package winnet

import (
	"context"
	"fmt"
	"io"
	"os/exec"

	"golang.org/x/sys/windows"
)

// Apply executes the generated networking plan with PowerShell. It requires an
// elevated process. When dryRun is true, it only prints the script.
func Apply(ctx context.Context, cfg Config, dryRun bool, out io.Writer) error {
	script, err := PowerShell(cfg)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	if ok, err := IsElevated(); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("winnet: administrator privileges are required; rerun from an elevated PowerShell")
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	b, err := cmd.CombinedOutput()
	if len(b) > 0 {
		_, _ = out.Write(b)
	}
	if err != nil {
		return fmt.Errorf("winnet: apply PowerShell plan: %w", err)
	}
	return nil
}

// Restore removes the CHIMERA-owned Windows route/DNS setup.
func Restore(ctx context.Context, cfg Config, dryRun bool, out io.Writer) error {
	script, err := RestorePowerShell(cfg)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	if ok, err := IsElevated(); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("winnet: administrator privileges are required; rerun from an elevated PowerShell")
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	b, err := cmd.CombinedOutput()
	if len(b) > 0 {
		_, _ = out.Write(b)
	}
	if err != nil {
		return fmt.Errorf("winnet: restore PowerShell plan: %w", err)
	}
	return nil
}

// Check verifies the CHIMERA-owned Windows route/DNS setup.
func Check(ctx context.Context, cfg Config, dryRun bool, out io.Writer) error {
	script, err := CheckPowerShell(cfg)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	b, err := cmd.CombinedOutput()
	if len(b) > 0 {
		_, _ = out.Write(b)
	}
	if err != nil {
		return fmt.Errorf("winnet: check PowerShell plan: %w", err)
	}
	return nil
}

// Elevate re-runs the current command through the Windows UAC prompt.
func Elevate(ctx context.Context, exe string, args []string, dryRun bool, out io.Writer) error {
	script, err := ElevatePowerShell(exe, args)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	b, err := cmd.CombinedOutput()
	if len(b) > 0 {
		_, _ = out.Write(b)
	}
	if err != nil {
		return fmt.Errorf("winnet: elevate PowerShell launcher: %w", err)
	}
	return nil
}

// IsElevated reports whether the current process is running as a member of the
// built-in Administrators group.
func IsElevated() (bool, error) {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("winnet: create administrators SID: %w", err)
	}
	ok, err := windows.Token(0).IsMember(adminSID)
	if err != nil {
		return false, fmt.Errorf("winnet: check administrator token: %w", err)
	}
	return ok, nil
}
