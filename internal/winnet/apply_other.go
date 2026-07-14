//go:build !windows

package winnet

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Apply prints dry-run plans on any OS, but real application is Windows-only.
func Apply(_ context.Context, cfg Config, dryRun bool, out io.Writer) error {
	script, err := PowerShell(cfg)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	return errors.New("winnet: applying Windows network setup is only supported on Windows")
}

// Restore prints dry-run plans on any OS, but real application is Windows-only.
func Restore(_ context.Context, cfg Config, dryRun bool, out io.Writer) error {
	script, err := RestorePowerShell(cfg)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	return errors.New("winnet: restoring Windows network setup is only supported on Windows")
}

// Check prints dry-run plans on any OS, but real checks are Windows-only.
func Check(_ context.Context, cfg Config, dryRun bool, out io.Writer) error {
	script, err := CheckPowerShell(cfg)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	return errors.New("winnet: checking Windows network setup is only supported on Windows")
}

// Elevate prints dry-run launchers on any OS, but real UAC elevation is Windows-only.
func Elevate(_ context.Context, exe string, args []string, dryRun bool, out io.Writer) error {
	script, err := ElevatePowerShell(exe, args)
	if err != nil {
		return err
	}
	if dryRun {
		_, err = fmt.Fprint(out, script)
		return err
	}
	return errors.New("winnet: elevated relaunch is only supported on Windows")
}

// IsElevated is meaningful only on Windows for this package.
func IsElevated() (bool, error) { return false, nil }
