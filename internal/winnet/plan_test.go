package winnet

import (
	"strings"
	"testing"
)

func TestPowerShellBuildsFullTunnelPlan(t *testing.T) {
	script, err := PowerShell(Config{
		InterfaceAlias: "chimera",
		AddressCIDR:    "10.255.0.2/30",
		DNS:            []string{"1.1.1.1", "8.8.8.8"},
		Endpoints:      []string{"203.0.113.10:443", "example.com", "203.0.113.10:443"},
	})
	if err != nil {
		t.Fatalf("PowerShell: %v", err)
	}
	for _, want := range []string{
		"New-NetIPAddress",
		"Set-DnsClientServerAddress",
		"0.0.0.0/1",
		"128.0.0.0/1",
		"Get-NetRoute -RemoteIPAddress",
		"203.0.113.10",
		"example.com",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "203.0.113.10:443") {
		t.Fatalf("endpoint port was not stripped:\n%s", script)
	}
	if strings.Count(script, "203.0.113.10") != 1 {
		t.Fatalf("endpoint list was not de-duplicated:\n%s", script)
	}
}

func TestPowerShellBuildsFirewallLeakGuard(t *testing.T) {
	script, err := PowerShell(Config{
		InterfaceAlias: "chimera",
		AddressCIDR:    "10.255.0.2/30",
		Firewall:       true,
	})
	if err != nil {
		t.Fatalf("PowerShell: %v", err)
	}
	for _, want := range []string{
		FirewallGroup,
		"Get-NetAdapter -Physical",
		"New-NetFirewallRule",
		"RemotePort 53",
		"Protocol UDP",
		"Protocol TCP",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("firewall script missing %q:\n%s", want, script)
		}
	}
}

func TestPowerShellBuildsKillswitch(t *testing.T) {
	script, err := PowerShell(Config{
		InterfaceAlias: "chimera",
		AddressCIDR:    "10.255.0.2/30",
		Endpoints:      []string{"203.0.113.10:443"},
		Killswitch:     true,
	})
	if err != nil {
		t.Fatalf("PowerShell: %v", err)
	}
	for _, want := range []string{
		"Set-NetFirewallProfile -All -DefaultOutboundAction Block",
		"CHIMERA killswitch allow loopback",
		"127.0.0.0/8",
		"CHIMERA killswitch allow TUN",
		"-InterfaceAlias $ifAlias",
		"CHIMERA killswitch allow endpoint",
		"foreach ($er in $endpointRoutes)",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("killswitch script missing %q:\n%s", want, script)
		}
	}
}

func TestPowerShellKillswitchOffOmitsDefaultOutboundBlock(t *testing.T) {
	script, err := PowerShell(Config{InterfaceAlias: "chimera", AddressCIDR: "10.255.0.2/30"})
	if err != nil {
		t.Fatalf("PowerShell: %v", err)
	}
	if strings.Contains(script, "DefaultOutboundAction Block") {
		t.Fatalf("killswitch=false script must not touch DefaultOutboundAction:\n%s", script)
	}
}

func TestPowerShellRejectsInvalidDNS(t *testing.T) {
	if _, err := PowerShell(Config{DNS: []string{"not-an-ip"}}); err == nil {
		t.Fatal("expected invalid DNS to fail")
	}
}

func TestPowerShellDefaults(t *testing.T) {
	script, err := PowerShell(Config{})
	if err != nil {
		t.Fatalf("PowerShell defaults: %v", err)
	}
	if !strings.Contains(script, DefaultInterfaceAlias) || !strings.Contains(script, "10.255.0.2") {
		t.Fatalf("defaults missing from script:\n%s", script)
	}
}

func TestRestorePowerShell(t *testing.T) {
	script, err := RestorePowerShell(Config{InterfaceAlias: "chimera", Endpoints: []string{"203.0.113.10:443"}})
	if err != nil {
		t.Fatalf("RestorePowerShell: %v", err)
	}
	for _, want := range []string{
		"Remove-NetRoute",
		"Remove-NetIPAddress",
		"ResetServerAddresses",
		"0.0.0.0/1",
		"128.0.0.0/1",
		"203.0.113.10",
		"/32",
		FirewallGroup,
		"Remove-NetFirewallRule",
		"Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("restore script missing %q:\n%s", want, script)
		}
	}
}

func TestCheckPowerShell(t *testing.T) {
	script, err := CheckPowerShell(Config{
		InterfaceAlias: "chimera",
		AddressCIDR:    "10.255.0.2/30",
		DNS:            []string{"1.1.1.1"},
		Endpoints:      []string{"203.0.113.10:443"},
		Firewall:       true,
	})
	if err != nil {
		t.Fatalf("CheckPowerShell: %v", err)
	}
	for _, want := range []string{
		"CHIMERA Windows network setup OK",
		"Get-NetIPAddress",
		"Get-DnsClientServerAddress",
		"0.0.0.0/1",
		"128.0.0.0/1",
		"203.0.113.10",
		FirewallGroup,
		"firewall leak guard is missing",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("check script missing %q:\n%s", want, script)
		}
	}
}

func TestCheckPowerShellKillswitch(t *testing.T) {
	script, err := CheckPowerShell(Config{
		InterfaceAlias: "chimera",
		AddressCIDR:    "10.255.0.2/30",
		Endpoints:      []string{"203.0.113.10:443"},
		Killswitch:     true,
	})
	if err != nil {
		t.Fatalf("CheckPowerShell: %v", err)
	}
	for _, want := range []string{
		"wantKillswitch = $true",
		"CHIMERA killswitch allow TUN",
		"killswitch TUN allow-rule is missing",
		"DefaultOutboundAction -ne 'Block'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("check script missing %q:\n%s", want, script)
		}
	}
}

func TestElevatePowerShellStripsElevateFlag(t *testing.T) {
	script, err := ElevatePowerShell(`C:\Tools\chimera.exe`, []string{
		"tun",
		"-server", "203.0.113.10:443",
		"-setup-os",
		"-setup-elevate",
		"-setup-firewall",
	})
	if err != nil {
		t.Fatalf("ElevatePowerShell: %v", err)
	}
	for _, want := range []string{
		"Start-Process",
		"-Verb RunAs",
		"-Wait",
		`C:\Tools\chimera.exe`,
		"-setup-os",
		"-setup-firewall",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("elevate script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "-setup-elevate") {
		t.Fatalf("elevate flag was not stripped:\n%s", script)
	}
}
