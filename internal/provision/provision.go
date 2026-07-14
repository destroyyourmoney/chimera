// Package provision closes the auto-provisioning loop: when telemetry reports
// endpoints burned (consistently unhealthy), a Provisioner brings up fresh ones
// and they are swapped into the live pool — no restart, no manual reconnect.
//
// The actual cloud/residential/CDN-fronted IP allocation is intentionally left to
// an operator-supplied command (CommandProvisioner): CHIMERA does not hardcode a
// cloud provider. The command prints a chimera subscription (the same signed
// `#!chimera-subscription-v1` format used by `-sub`) to stdout; its endpoints are
// parsed, added to the pool, and the burned ones removed.
package provision

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"chimera/internal/carrier"
	"chimera/internal/subscription"
)

// Provisioner produces fresh endpoint configs to replace burned ones.
type Provisioner interface {
	// Provision returns up to n fresh endpoint configs. n is a hint (the number of
	// burned endpoints); a Provisioner may return fewer or more.
	Provision(ctx context.Context, n int) ([]carrier.Config, error)
}

// PoolMutator is the runtime endpoint-mutation surface, satisfied by
// *endpoint.Pool and *endpoint.AutoPool.
type PoolMutator interface {
	AddEndpoints([]carrier.Config) int
	RemoveEndpoints([]string) int
}

// CommandProvisioner runs an operator command that prints a chimera subscription
// to stdout. The requested count is exposed to the command as the environment
// variable CHIMERA_PROVISION_N. An optional HMAC key verifies a signed subscription.
type CommandProvisioner struct {
	Name string
	Args []string
	Env  []string // optional extra environment variables appended after os.Environ
	Key  []byte   // optional HMAC-SHA256 key for subscription signature verification
}

// ShellCommandProvisioner builds a CommandProvisioner using the platform shell.
// Windows uses PowerShell; Unix-like systems use sh -c.
func ShellCommandProvisioner(command string, key []byte) CommandProvisioner {
	if runtime.GOOS == "windows" {
		return CommandProvisioner{
			Name: "powershell.exe",
			Args: []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command},
			Key:  key,
		}
	}
	return CommandProvisioner{Name: "sh", Args: []string{"-c", command}, Key: key}
}

// Provision runs the command and parses its stdout into endpoint configs.
func (c CommandProvisioner) Provision(ctx context.Context, n int) ([]carrier.Config, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("CHIMERA_PROVISION_N=%d", n))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("provision: command %q failed: %w", c.Name, err)
	}
	cfgs, err := subscription.Parse(&out, c.Key)
	if err != nil {
		return nil, fmt.Errorf("provision: parse command output: %w", err)
	}
	return cfgs, nil
}

// Rotate provisions fresh endpoints and swaps out the burned ones. It adds first
// and only removes the burned servers if at least one fresh endpoint was added, so
// a failed provision never shrinks the working pool. Suitable as a telemetry
// RotationHook body.
func Rotate(ctx context.Context, pool PoolMutator, prov Provisioner, burnedServers []string) error {
	fresh, err := prov.Provision(ctx, len(burnedServers))
	if err != nil {
		return err
	}
	added := pool.AddEndpoints(fresh)
	if added == 0 {
		return fmt.Errorf("provision: no new endpoints provisioned (got %d configs, all duplicates?)", len(fresh))
	}
	pool.RemoveEndpoints(burnedServers)
	return nil
}
