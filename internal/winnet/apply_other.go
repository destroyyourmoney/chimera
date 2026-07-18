//go:build !windows

package winnet

import (
	"context"
	"errors"
	"fmt"
	"io"
)

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

func IsElevated() (bool, error) { return false, nil }
