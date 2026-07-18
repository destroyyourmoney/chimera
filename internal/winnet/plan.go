package winnet

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultInterfaceAlias = "chimera"
	DefaultAddressCIDR    = "10.255.0.2/30"
	FirewallGroup         = "CHIMERA killswitch"
)

type Config struct {
	InterfaceAlias string
	AddressCIDR    string
	DNS            []string
	Endpoints      []string
	Firewall       bool
	Killswitch     bool
}

func ElevatePowerShell(exe string, args []string) (string, error) {
	exe = strings.TrimSpace(exe)
	if exe == "" {
		return "", fmt.Errorf("winnet: empty executable path")
	}
	if !filepathLike(exe) {
		if resolved, err := os.Executable(); err == nil && strings.TrimSpace(resolved) != "" {
			exe = resolved
		}
	}

	cleanArgs := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-setup-elevate" {
			continue
		}
		cleanArgs = append(cleanArgs, arg)
	}

	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$exe = " + psQuote(exe) + "\n")
	b.WriteString("$args = @(" + psArray(cleanArgs) + ")\n")
	b.WriteString("Start-Process -FilePath $exe -ArgumentList $args -Verb RunAs -Wait\n")
	return b.String(), nil
}

func (c Config) Normalize() Config {
	if strings.TrimSpace(c.InterfaceAlias) == "" {
		c.InterfaceAlias = DefaultInterfaceAlias
	}
	if strings.TrimSpace(c.AddressCIDR) == "" {
		c.AddressCIDR = DefaultAddressCIDR
	}
	c.InterfaceAlias = strings.TrimSpace(c.InterfaceAlias)
	c.AddressCIDR = strings.TrimSpace(c.AddressCIDR)
	c.DNS = cleanList(c.DNS)
	c.Endpoints = cleanEndpoints(c.Endpoints)
	return c
}

func PowerShell(c Config) (string, error) {
	c = c.Normalize()
	addr, err := netip.ParsePrefix(c.AddressCIDR)
	if err != nil || !addr.Addr().Is4() {
		return "", fmt.Errorf("winnet: invalid IPv4 CIDR %q", c.AddressCIDR)
	}
	if err := validateDNS(c.DNS); err != nil {
		return "", err
	}

	ip := addr.Addr().String()
	prefix := addr.Bits()

	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$ifAlias = " + psQuote(c.InterfaceAlias) + "\n")
	b.WriteString("$endpointNames = @(" + psArray(c.Endpoints) + ")\n")

	b.WriteString("$fwGroup = " + psQuote(FirewallGroup) + "\n")

	b.WriteString("Get-NetRoute -InterfaceAlias $ifAlias -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n")
	b.WriteString("Get-NetRoute -InterfaceAlias $ifAlias -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n")
	b.WriteString("$endpointRoutes = @()\n")
	b.WriteString("foreach ($name in $endpointNames) {\n")
	b.WriteString("  $ips = @()\n")
	b.WriteString("  $parsed = [System.Net.IPAddress]::None\n")
	b.WriteString("  if ([System.Net.IPAddress]::TryParse($name, [ref]$parsed) -and $parsed.AddressFamily -eq 'InterNetwork') { $ips += $parsed.IPAddressToString }\n")
	b.WriteString("  else { $ips += [System.Net.Dns]::GetHostAddresses($name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString } }\n")
	b.WriteString("  foreach ($ip in $ips) {\n")

	b.WriteString("    $r = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | Select-Object -First 1\n")
	b.WriteString("    if ($null -ne $r) { $endpointRoutes += [pscustomobject]@{ IP = $ip; InterfaceIndex = $r.InterfaceIndex; NextHop = $r.NextHop } }\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	b.WriteString("$if = Get-NetAdapter -InterfaceAlias $ifAlias -ErrorAction Stop\n")
	if c.Firewall {
		b.WriteString("$nonTunAliases = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne $ifAlias -and $_.Status -ne 'Disabled' } | ForEach-Object { $_.InterfaceAlias })\n")
	}
	b.WriteString("Get-NetIPAddress -InterfaceAlias $ifAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue\n")
	b.WriteString("New-NetIPAddress -InterfaceAlias $ifAlias -IPAddress " + psQuote(ip) + " -PrefixLength " + strconv.Itoa(prefix) + " -PolicyStore ActiveStore | Out-Null\n")
	if len(c.DNS) > 0 {
		b.WriteString("Set-DnsClientServerAddress -InterfaceAlias $ifAlias -ServerAddresses @(" + psArray(c.DNS) + ")\n")
	}

	b.WriteString("New-NetRoute -InterfaceAlias $ifAlias -DestinationPrefix '0.0.0.0/1' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null\n")
	b.WriteString("New-NetRoute -InterfaceAlias $ifAlias -DestinationPrefix '128.0.0.0/1' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null\n")
	b.WriteString("foreach ($r in $endpointRoutes) {\n")
	b.WriteString("  $prefix = \"$($r.IP)/32\"\n")
	b.WriteString("  Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object { $_.PolicyStore -eq 'ActiveStore' } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n")
	b.WriteString("  if ($r.NextHop -and $r.NextHop -ne '0.0.0.0') { New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $r.InterfaceIndex -NextHop $r.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null }\n")
	b.WriteString("  else { New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $r.InterfaceIndex -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null }\n")
	b.WriteString("}\n")
	if c.Firewall || c.Killswitch {
		b.WriteString("Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n")
	}
	if c.Firewall {
		b.WriteString("foreach ($alias in $nonTunAliases) {\n")
		b.WriteString("  New-NetFirewallRule -DisplayName \"CHIMERA block DNS leak UDP ($alias)\" -Group $fwGroup -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $alias -Protocol UDP -RemotePort 53 | Out-Null\n")
		b.WriteString("  New-NetFirewallRule -DisplayName \"CHIMERA block DNS leak TCP ($alias)\" -Group $fwGroup -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $alias -Protocol TCP -RemotePort 53 | Out-Null\n")
		b.WriteString("}\n")
	}
	if c.Killswitch {

		b.WriteString("Set-NetFirewallProfile -All -DefaultOutboundAction Block\n")
		b.WriteString("New-NetFirewallRule -DisplayName 'CHIMERA killswitch allow loopback' -Group $fwGroup -Direction Outbound -Action Allow -Enabled True -Profile Any -RemoteAddress 127.0.0.0/8 | Out-Null\n")
		b.WriteString("New-NetFirewallRule -DisplayName 'CHIMERA killswitch allow TUN' -Group $fwGroup -Direction Outbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $ifAlias | Out-Null\n")
		b.WriteString("foreach ($er in $endpointRoutes) {\n")
		b.WriteString("  New-NetFirewallRule -DisplayName \"CHIMERA killswitch allow endpoint ($($er.IP))\" -Group $fwGroup -Direction Outbound -Action Allow -Enabled True -Profile Any -RemoteAddress $er.IP | Out-Null\n")
		b.WriteString("}\n")
	}
	return b.String(), nil
}

func RestorePowerShell(c Config) (string, error) {
	c = c.Normalize()
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$ifAlias = " + psQuote(c.InterfaceAlias) + "\n")
	b.WriteString("$endpointNames = @(" + psArray(c.Endpoints) + ")\n")
	b.WriteString("$fwGroup = " + psQuote(FirewallGroup) + "\n")

	b.WriteString("Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n")

	b.WriteString("Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured\n")
	b.WriteString("foreach ($name in $endpointNames) {\n")
	b.WriteString("  $ips = @()\n")
	b.WriteString("  $parsed = [System.Net.IPAddress]::None\n")
	b.WriteString("  if ([System.Net.IPAddress]::TryParse($name, [ref]$parsed) -and $parsed.AddressFamily -eq 'InterNetwork') { $ips += $parsed.IPAddressToString }\n")
	b.WriteString("  else { $ips += [System.Net.Dns]::GetHostAddresses($name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString } }\n")
	b.WriteString("  foreach ($ip in $ips) { Get-NetRoute -DestinationPrefix \"$ip/32\" -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }\n")
	b.WriteString("}\n")
	b.WriteString("$if = Get-NetAdapter -InterfaceAlias $ifAlias -ErrorAction SilentlyContinue\n")
	b.WriteString("if ($null -ne $if) {\n")
	b.WriteString("  Get-NetRoute -InterfaceAlias $ifAlias -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n")
	b.WriteString("  Get-NetRoute -InterfaceAlias $ifAlias -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n")
	b.WriteString("  Get-NetIPAddress -InterfaceAlias $ifAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue\n")
	b.WriteString("  Set-DnsClientServerAddress -InterfaceAlias $ifAlias -ResetServerAddresses -ErrorAction SilentlyContinue\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func CheckPowerShell(c Config) (string, error) {
	c = c.Normalize()
	addr, err := netip.ParsePrefix(c.AddressCIDR)
	if err != nil || !addr.Addr().Is4() {
		return "", fmt.Errorf("winnet: invalid IPv4 CIDR %q", c.AddressCIDR)
	}
	if err := validateDNS(c.DNS); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$ifAlias = " + psQuote(c.InterfaceAlias) + "\n")
	b.WriteString("$wantIP = " + psQuote(addr.Addr().String()) + "\n")
	b.WriteString("$wantPrefix = " + strconv.Itoa(addr.Bits()) + "\n")
	b.WriteString("$wantDNS = @(" + psArray(c.DNS) + ")\n")
	b.WriteString("$endpointNames = @(" + psArray(c.Endpoints) + ")\n")
	b.WriteString("$wantFirewall = $" + psBool(c.Firewall) + "\n")
	b.WriteString("$wantKillswitch = $" + psBool(c.Killswitch) + "\n")
	b.WriteString("$fwGroup = " + psQuote(FirewallGroup) + "\n")
	b.WriteString("$if = Get-NetAdapter -InterfaceAlias $ifAlias -ErrorAction Stop\n")
	b.WriteString("$ip = Get-NetIPAddress -InterfaceAlias $ifAlias -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -eq $wantIP -and $_.PrefixLength -eq $wantPrefix } | Select-Object -First 1\n")
	b.WriteString("if ($null -eq $ip) { throw \"CHIMERA setup check failed: interface address $wantIP/$wantPrefix is missing\" }\n")
	b.WriteString("foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1')) {\n")
	b.WriteString("  $r = Get-NetRoute -InterfaceAlias $ifAlias -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Select-Object -First 1\n")
	b.WriteString("  if ($null -eq $r) { throw \"CHIMERA setup check failed: route $prefix via $ifAlias is missing\" }\n")
	b.WriteString("}\n")
	b.WriteString("if ($wantDNS.Count -gt 0) {\n")
	b.WriteString("  $dns = (Get-DnsClientServerAddress -InterfaceAlias $ifAlias -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses\n")
	b.WriteString("  foreach ($s in $wantDNS) { if ($dns -notcontains $s) { throw \"CHIMERA setup check failed: DNS $s is missing\" } }\n")
	b.WriteString("}\n")
	b.WriteString("foreach ($name in $endpointNames) {\n")
	b.WriteString("  $ips = @()\n")
	b.WriteString("  $parsed = [System.Net.IPAddress]::None\n")
	b.WriteString("  if ([System.Net.IPAddress]::TryParse($name, [ref]$parsed) -and $parsed.AddressFamily -eq 'InterNetwork') { $ips += $parsed.IPAddressToString }\n")
	b.WriteString("  else { $ips += [System.Net.Dns]::GetHostAddresses($name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString } }\n")
	b.WriteString("  foreach ($ip in $ips) {\n")
	b.WriteString("    $pin = Get-NetRoute -DestinationPrefix \"$ip/32\" -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne $ifAlias } | Select-Object -First 1\n")
	b.WriteString("    if ($null -eq $pin) { throw \"CHIMERA setup check failed: endpoint pin $ip/32 is missing\" }\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	b.WriteString("if ($wantFirewall) {\n")
	b.WriteString("  $rules = @(Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue)\n")
	b.WriteString("  if ($rules.Count -eq 0) { throw \"CHIMERA setup check failed: firewall leak guard is missing\" }\n")
	b.WriteString("}\n")
	b.WriteString("if ($wantKillswitch) {\n")
	b.WriteString("  $tunAllow = Get-NetFirewallRule -Group $fwGroup -DisplayName 'CHIMERA killswitch allow TUN' -ErrorAction SilentlyContinue\n")
	b.WriteString("  if ($null -eq $tunAllow) { throw \"CHIMERA setup check failed: killswitch TUN allow-rule is missing\" }\n")
	b.WriteString("  $profiles = @(Get-NetFirewallProfile -All | Where-Object { $_.DefaultOutboundAction -ne 'Block' })\n")
	b.WriteString("  if ($profiles.Count -gt 0) { throw \"CHIMERA setup check failed: DefaultOutboundAction is not Block on profile(s) $($profiles.Name -join ', ')\" }\n")
	b.WriteString("}\n")
	b.WriteString("Write-Output 'CHIMERA Windows network setup OK'\n")
	return b.String(), nil
}

func cleanList(v []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range v {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func cleanEndpoints(v []string) []string {
	cleaned := make([]string, 0, len(v))
	for _, s := range v {
		s = strings.TrimSpace(s)
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = strings.Trim(h, "[]")
		}
		cleaned = append(cleaned, s)
	}
	return cleanList(cleaned)
}

func validateDNS(servers []string) error {
	for _, s := range servers {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("winnet: DNS server %q is not an IPv4 address", s)
		}
	}
	return nil
}

func psArray(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = psQuote(item)
	}
	return strings.Join(quoted, ", ")
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func psBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func filepathLike(s string) bool {
	return strings.ContainsAny(s, `\/:`)
}
