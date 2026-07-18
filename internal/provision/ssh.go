package provision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"chimera/internal/link"
	"chimera/internal/subscription"
)

const pubMarker = "CHIMERA_PUB="

const portInUseMarker = "CHIMERA_PORT_IN_USE"

const (
	defaultSSHPort      = 22
	defaultStealHost    = "www.microsoft.com:443"
	defaultServerPort   = 443
	defaultShortIDCount = 1
	defaultRepo         = "https://github.com/destroyyourmoney/chimera.git"
	defaultRef          = "main"
	defaultImage        = "chimera-server:latest"
	defaultContainer    = "chimera-server"
	defaultTransport    = "auto"
	serverBuildTags     = "chimera_utls chimera_quic chimera_ss chimera_dot"
	remoteDir           = "/opt/chimera"
	dockerfilePath      = "docker/Dockerfile"

	chimeraLabel = "io.chimera.managed=true"
)

type ListenerSpec struct {
	Transport string
	Port      int
}

type DeployedListener struct {
	Transport string
	Port      int
}

type DeploySpec struct {
	Host           string
	SSHPort        int
	StealHost      string
	ServerPort     int
	ExtraListeners []ListenerSpec
	ShortIDCount   int
	Repo           string
	Ref            string
	Image          string
	Container      string
	Transport      string
	SNI            string
}

type DeployResult struct {
	PublicKey    string
	ShortIDs     []string
	Links        []string
	Subscription string

	Listeners []DeployedListener
}

type CommandRunner interface {
	Run(ctx context.Context, script string) (stdout string, err error)
}

type SSHDeployer struct {
	Runner  CommandRunner
	SignKey []byte
}

func (d *SSHDeployer) Deploy(ctx context.Context, spec DeploySpec) (DeployResult, error) {
	spec = normalize(spec)
	if d.Runner == nil {
		return DeployResult{}, fmt.Errorf("provision: nil runner")
	}
	if err := validateExtraListeners(spec); err != nil {
		return DeployResult{}, err
	}

	sids, err := mintShortIDs(spec.ShortIDCount)
	if err != nil {
		return DeployResult{}, err
	}

	script, err := buildDeployScript(spec, sids)
	if err != nil {
		return DeployResult{}, err
	}

	out, err := d.Runner.Run(ctx, script)
	if err != nil {
		if strings.Contains(err.Error(), portInUseMarker) ||
			strings.Contains(err.Error(), "address already in use") {
			return DeployResult{}, fmt.Errorf(
				"provision: one of the requested ports (%s) is already in "+
					"use on this server (another process or a leftover "+
					"container is bound to it) -- free the port or pick a "+
					"different one and try again", describePorts(spec))
		}
		return DeployResult{}, fmt.Errorf("provision: remote deploy failed: %w", err)
	}

	pub, err := parsePub(out)
	if err != nil {
		return DeployResult{}, err
	}

	return d.buildResult(spec, sids, pub)
}

func describePorts(spec DeploySpec) string {
	ports := []string{fmt.Sprintf("%d", spec.ServerPort)}
	for _, l := range spec.ExtraListeners {
		ports = append(ports, fmt.Sprintf("%d", l.Port))
	}
	return strings.Join(ports, ", ")
}

func (d *SSHDeployer) buildResult(spec DeploySpec, sids []string, pub string) (DeployResult, error) {
	res := DeployResult{PublicKey: pub, ShortIDs: sids}
	res.Listeners = append(res.Listeners, DeployedListener{Transport: "reality", Port: spec.ServerPort})
	for _, l := range spec.ExtraListeners {
		res.Listeners = append(res.Listeners, DeployedListener{Transport: l.Transport, Port: l.Port})
	}
	host, port := splitHostPort(spec.Host, spec.ServerPort)
	for _, sid := range sids {
		res.Links = append(res.Links, link.Build(link.Profile{
			Host: host,
			Port: port,
			Pbk:  pub,
			Sid:  sid,
			Sni:  spec.SNI,
			Mode: spec.Transport,
			Tag:  "chimera@" + host,
		}))
	}

	primary := res.Links[0]
	var b strings.Builder
	b.WriteString("#!chimera-subscription-v1\n")
	if len(d.SignKey) > 0 {
		b.WriteString("# sig: " + subscription.Sign([]string{primary}, d.SignKey) + "\n")
	}
	b.WriteString(primary + "\n")
	res.Subscription = b.String()
	return res, nil
}

func validateExtraListeners(spec DeploySpec) error {
	seenPorts := map[int]bool{spec.ServerPort: true}
	for _, l := range spec.ExtraListeners {
		switch l.Transport {
		case "quic", "ss", "dot":
		case "reality", "tcp", "":
			return fmt.Errorf("provision: ExtraListeners entry has transport %q -- "+
				"Reality/TCP is always the primary listener (ServerPort), don't repeat it here", l.Transport)
		default:
			return fmt.Errorf("provision: unknown ExtraListeners transport %q (want quic, ss, or dot)", l.Transport)
		}
		if l.Port <= 0 || l.Port > 65535 {
			return fmt.Errorf("provision: ExtraListeners transport %q has invalid port %d", l.Transport, l.Port)
		}
		if seenPorts[l.Port] {
			return fmt.Errorf("provision: port %d is used by more than one listener", l.Port)
		}
		seenPorts[l.Port] = true
	}
	return nil
}

func normalize(s DeploySpec) DeploySpec {
	if s.SSHPort == 0 {
		s.SSHPort = defaultSSHPort
	}
	if s.StealHost == "" {
		s.StealHost = defaultStealHost
	}
	if s.ServerPort == 0 {
		s.ServerPort = defaultServerPort
	}
	if s.ShortIDCount <= 0 {
		s.ShortIDCount = defaultShortIDCount
	}
	if s.Repo == "" {
		s.Repo = defaultRepo
	}
	if s.Ref == "" {
		s.Ref = defaultRef
	}
	if s.Image == "" {
		s.Image = defaultImage
	}
	if s.Container == "" {
		s.Container = defaultContainer
	}
	if s.Transport == "" {
		s.Transport = defaultTransport
	}
	if s.SNI == "" {

		h := s.StealHost
		if i := strings.LastIndex(h, ":"); i > 0 {
			h = h[:i]
		}
		s.SNI = h
	}
	return s
}

func mintShortIDs(n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("provision: mint short ID: %w", err)
		}
		out = append(out, hex.EncodeToString(b[:]))
	}
	return out, nil
}

func parsePub(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, pubMarker) {
			pub := strings.TrimSpace(strings.TrimPrefix(line, pubMarker))
			if pub == "" {
				return "", fmt.Errorf("provision: empty public key in remote output")
			}
			return pub, nil
		}
	}
	return "", fmt.Errorf("provision: no %q marker in remote output (deploy may have failed)", pubMarker)
}

func (d *SSHDeployer) Teardown(ctx context.Context) error {
	if d.Runner == nil {
		return fmt.Errorf("provision: nil runner")
	}
	if _, err := d.Runner.Run(ctx, teardownScript()); err != nil {
		return fmt.Errorf("provision: remote teardown failed: %w", err)
	}
	return nil
}

func teardownScript() string {
	q := func(s string) string { return "'" + s + "'" }
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("if command -v docker >/dev/null 2>&1; then\n")
	b.WriteString("  IDS=$(docker ps -aq --filter " + q("label="+chimeraLabel) + " 2>/dev/null)\n")
	b.WriteString("  if [ -n \"$IDS\" ]; then docker rm -f $IDS >/dev/null 2>&1 || true; fi\n")
	b.WriteString("fi\n")
	return b.String()
}

func splitHostPort(host string, defPort int) (string, string) {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], "]") {
		return host[:i], host[i+1:]
	}
	return host, fmt.Sprintf("%d", defPort)
}
