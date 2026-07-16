// ssh.go implements the Operator-mode server deployment: over an SSH session it
// installs Docker (if absent), clones the CHIMERA sources from GitHub, builds the
// server image, generates a keypair *on the VPS* (the private key never leaves the
// server), launches the server container, and returns a chimera:// link plus an
// optionally-signed subscription for the operator to distribute.
//
// The deployment logic here is transport-agnostic and depends only on a
// CommandRunner, so it is fully unit-testable with a fake runner. The real
// SSH-backed runner lives in ssh_transport.go.
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

// pubMarker is the line the remote script prints carrying the server's public
// key. The deployer parses only this line; the private key stays on the VPS.
const pubMarker = "CHIMERA_PUB="

// portInUseMarker is what the remote script's port pre-check (script.go)
// prints to stderr when the requested server port is already bound by
// something else on the VPS. Deploy pattern-matches on it (and on Docker's
// own "address already in use" wording, for the race where something grabs
// the port mid-build) to turn a buried shell/Docker error into a message an
// operator can act on immediately.
const portInUseMarker = "CHIMERA_PORT_IN_USE"

// defaults for a DeploySpec; applied by normalize.
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

	// chimeraLabel is applied to every container this package's deploy
	// script creates (see script.go's docker run), so a later port-conflict
	// self-heal or a Teardown call can identify "a container this tooling
	// created" without relying on the container name alone (spec.Container
	// can be customized) or risking removing an operator's unrelated
	// container that merely happens to occupy the same port/name.
	chimeraLabel = "io.chimera.managed=true"
)

// ListenerSpec is one additional transport listener to launch on the same
// box as the primary Reality/TCP one (ROADMAP2 §3/§4 multi-transport
// support): "the anti-censorship picker offers 4 transports, so a fully
// stocked server should actually run all 4 processes, not just Reality".
// Transport is one of "quic", "ss", "dot" -- Reality is always the primary
// listener (DeploySpec.ServerPort) and must not be repeated here.
type ListenerSpec struct {
	Transport string
	Port      int
}

// DeployedListener is one listener buildDeployScript actually launched --
// what DeployResult.Listeners reports back, e.g. for an operator script to
// loop over and call `chimera-control-cli catalog add-listener` once per
// entry (or pass the same list straight into `catalog add`'s inline
// `listeners`, since the admin API accepts both -- see adminapi.go).
type DeployedListener struct {
	Transport string
	Port      int
}

// DeploySpec describes a single server deployment requested by the operator.
type DeploySpec struct {
	Host           string         // VPS host/IP — the SSH target and the link host
	SSHPort        int            // SSH port (default 22)
	StealHost      string         // steal-host "host:port" (default www.microsoft.com:443)
	ServerPort     int            // CHIMERA listen port (default 443) -- the primary Reality/TCP listener
	ExtraListeners []ListenerSpec // additional transport listeners on the same box, same keypair (default none)
	ShortIDCount   int            // number of short IDs to mint (default 1)
	Repo           string         // git URL to clone (default GitHub CHIMERA repo)
	Ref            string         // branch/tag/commit (default main)
	Image          string         // docker image tag (default chimera-server:latest)
	Container      string         // container name (default chimera-server)
	Transport      string         // link transport hint: auto|quic|tcp (default auto)
	SNI            string         // link SNI (default = steal-host's hostname)
}

// DeployResult is what the operator hands to users (Subscription) or shares
// directly (Links). PublicKey and ShortIDs are surfaced for reference.
type DeployResult struct {
	PublicKey    string
	ShortIDs     []string
	Links        []string
	Subscription string

	// Listeners is every transport listener this deploy actually launched --
	// always starts with {"reality", spec.ServerPort}, followed by one entry
	// per spec.ExtraListeners in order. Feed this straight into
	// internal/controlplane's catalog (CatalogServer.Listeners or repeated
	// AddListener calls) to register the server with every transport it
	// really offers, not just Reality.
	Listeners []DeployedListener
}

// CommandRunner executes one shell script on the target host and returns its
// combined stdout. Implemented by the SSH transport (ssh_transport.go) and by
// test fakes.
type CommandRunner interface {
	Run(ctx context.Context, script string) (stdout string, err error)
}

// SSHDeployer deploys a CHIMERA server over a CommandRunner.
type SSHDeployer struct {
	Runner  CommandRunner
	SignKey []byte // optional HMAC-SHA256 key; when set the subscription is signed
}

// Deploy runs the full provisioning sequence and returns the operator artifacts.
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

// describePorts renders every port this deploy will bind, for the
// port-in-use error message -- the primary Reality/TCP port plus each
// ExtraListeners entry's port.
func describePorts(spec DeploySpec) string {
	ports := []string{fmt.Sprintf("%d", spec.ServerPort)}
	for _, l := range spec.ExtraListeners {
		ports = append(ports, fmt.Sprintf("%d", l.Port))
	}
	return strings.Join(ports, ", ")
}

// buildResult assembles links + subscription from the deployment outputs.
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
	// A subscription for one server uses a single endpoint (the first short ID);
	// extra short IDs are returned in res.ShortIDs for the operator to hand out.
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

// validateExtraListeners rejects malformed multi-transport requests before
// any script gets built/run: an unknown transport would silently pass
// `-transport garbage` to `chimera server` (which just fails remotely, much
// harder to diagnose than a local error), and a port collision (with the
// primary listener or between two extras) would make the second `docker
// run` fail with a confusing bind error instead of a clear one up front.
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

// normalize fills zero-valued spec fields with defaults.
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
		// Derive the link SNI from the steal-host's hostname.
		h := s.StealHost
		if i := strings.LastIndex(h, ":"); i > 0 {
			h = h[:i]
		}
		s.SNI = h
	}
	return s
}

// mintShortIDs returns n random 4-byte short IDs as hex strings.
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

// parsePub extracts the CHIMERA_PUB=<key> line from remote output.
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

// Teardown removes any CHIMERA-managed Docker container(s) (see chimeraLabel)
// from the host reachable via d.Runner -- the counterpart to Deploy, used
// when an operator deletes a server from the app so the VPS doesn't keep
// running (and billing for) an orphaned container indefinitely. Identifying
// containers by label rather than a fixed/expected name means it works
// regardless of what Container name the original Deploy used.
func (d *SSHDeployer) Teardown(ctx context.Context) error {
	if d.Runner == nil {
		return fmt.Errorf("provision: nil runner")
	}
	if _, err := d.Runner.Run(ctx, teardownScript()); err != nil {
		return fmt.Errorf("provision: remote teardown failed: %w", err)
	}
	return nil
}

// teardownScript renders the remote script Teardown runs. No operator input
// is interpolated, so there's no injection surface to guard here the way
// buildDeployScript does.
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

// splitHostPort splits "host" or "host:port"; falls back to the given default port.
func splitHostPort(host string, defPort int) (string, string) {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], "]") {
		return host[:i], host[i+1:]
	}
	return host, fmt.Sprintf("%d", defPort)
}
