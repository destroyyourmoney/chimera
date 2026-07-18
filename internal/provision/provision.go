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

type Provisioner interface {
	Provision(ctx context.Context, n int) ([]carrier.Config, error)
}

type PoolMutator interface {
	AddEndpoints([]carrier.Config) int
	RemoveEndpoints([]string) int
}

type CommandProvisioner struct {
	Name string
	Args []string
	Env  []string
	Key  []byte
}

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
