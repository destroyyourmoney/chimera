package provision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"chimera/internal/carrier"
	"chimera/internal/link"
)

// fakePool records AddEndpoints/RemoveEndpoints calls.
type fakePool struct {
	added   []carrier.Config
	removed []string
	addN    int // value AddEndpoints reports as added
}

func (f *fakePool) AddEndpoints(cfgs []carrier.Config) int {
	f.added = append(f.added, cfgs...)
	if f.addN != 0 {
		return f.addN
	}
	return len(cfgs)
}
func (f *fakePool) RemoveEndpoints(servers []string) int {
	f.removed = append(f.removed, servers...)
	return len(servers)
}

type fakeProv struct {
	cfgs []carrier.Config
	err  error
	gotN int
}

func (p *fakeProv) Provision(_ context.Context, n int) ([]carrier.Config, error) {
	p.gotN = n
	return p.cfgs, p.err
}

func TestRotate_AddsThenRemoves(t *testing.T) {
	pool := &fakePool{}
	prov := &fakeProv{cfgs: []carrier.Config{{Server: "new1:443"}, {Server: "new2:443"}}}
	burned := []string{"old1:443", "old2:443"}

	if err := Rotate(context.Background(), pool, prov, burned); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if prov.gotN != 2 {
		t.Fatalf("provisioner got n=%d, want 2 (burned count)", prov.gotN)
	}
	if len(pool.added) != 2 {
		t.Fatalf("added %d endpoints, want 2", len(pool.added))
	}
	if len(pool.removed) != 2 {
		t.Fatalf("removed %d servers, want 2", len(pool.removed))
	}
}

func TestRotate_ProvisionErrorDoesNotShrinkPool(t *testing.T) {
	pool := &fakePool{}
	prov := &fakeProv{err: errors.New("cloud API down")}
	if err := Rotate(context.Background(), pool, prov, []string{"old:443"}); err == nil {
		t.Fatal("expected error from failed provision")
	}
	if len(pool.added) != 0 || len(pool.removed) != 0 {
		t.Fatal("pool must not be mutated when provisioning fails")
	}
}

func TestRotate_NoNewEndpointsDoesNotRemove(t *testing.T) {
	// AddEndpoints reports 0 added (e.g. all duplicates): the burned endpoints must
	// NOT be removed, or the pool could be emptied.
	pool := &zeroAddPool{}
	prov := &fakeProv{cfgs: []carrier.Config{{Server: "dup:443"}}}
	if err := Rotate(context.Background(), pool, prov, []string{"old:443"}); err == nil {
		t.Fatal("expected error when no new endpoints were added")
	}
	if len(pool.removed) != 0 {
		t.Fatal("must not remove burned endpoints when nothing fresh was added")
	}
}

type zeroAddPool struct{ removed []string }

func (z *zeroAddPool) AddEndpoints([]carrier.Config) int { return 0 }
func (z *zeroAddPool) RemoveEndpoints(s []string) int    { z.removed = append(z.removed, s...); return 0 }

func TestCommandProvisioner_ParsesSubscription(t *testing.T) {
	// A command that prints a valid (unsigned) chimera subscription built via link.Build.
	uri := link.Build(link.Profile{Host: "host1", Port: "443", Pbk: "AAA", Sni: "example.com"})
	sub := "#!chimera-subscription-v1\n" + uri + "\n"
	prov := CommandProvisioner{
		Name: os.Args[0],
		Args: []string{"-test.run=TestCommandProvisionerHelper"},
		Env:  []string{"CHIMERA_TEST_HELPER=1", "CHIMERA_TEST_SUB=" + sub},
	}
	cfgs, err := prov.Provision(context.Background(), 1)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("parsed %d configs, want 1", len(cfgs))
	}
	if cfgs[0].Server == "" {
		t.Fatalf("parsed config has empty Server: %+v", cfgs[0])
	}
}

func TestCommandProvisionerHelper(t *testing.T) {
	if os.Getenv("CHIMERA_TEST_HELPER") != "1" {
		return
	}
	fmt.Print(os.Getenv("CHIMERA_TEST_SUB"))
	os.Exit(0)
}

func TestShellCommandProvisionerUsesPlatformShell(t *testing.T) {
	prov := ShellCommandProvisioner("echo ok", nil)
	if runtime.GOOS == "windows" {
		if prov.Name != "powershell.exe" {
			t.Fatalf("windows shell = %q, want powershell.exe", prov.Name)
		}
		return
	}
	if prov.Name != "sh" {
		t.Fatalf("unix shell = %q, want sh", prov.Name)
	}
}
