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
	serverBuildTags     = "chimera_utls chimera_quic"
	remoteDir           = "/opt/chimera"
	dockerfilePath      = "docker/Dockerfile"
)

// DeploySpec describes a single server deployment requested by the operator.
type DeploySpec struct {
	Host         string // VPS host/IP — the SSH target and the link host
	SSHPort      int    // SSH port (default 22)
	StealHost    string // steal-host "host:port" (default www.microsoft.com:443)
	ServerPort   int    // CHIMERA listen port (default 443)
	ShortIDCount int    // number of short IDs to mint (default 1)
	Repo         string // git URL to clone (default GitHub CHIMERA repo)
	Ref          string // branch/tag/commit (default main)
	Image        string // docker image tag (default chimera-server:latest)
	Container    string // container name (default chimera-server)
	Transport    string // link transport hint: auto|quic|tcp (default auto)
	SNI          string // link SNI (default = steal-host's hostname)
}

// DeployResult is what the operator hands to users (Subscription) or shares
// directly (Links). PublicKey and ShortIDs are surfaced for reference.
type DeployResult struct {
	PublicKey    string
	ShortIDs     []string
	Links        []string
	Subscription string
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
				"provision: port %d is already in use on this server "+
					"(another process or a leftover container is bound to "+
					"it) -- free the port or pick a different one and try "+
					"again", spec.ServerPort)
		}
		return DeployResult{}, fmt.Errorf("provision: remote deploy failed: %w", err)
	}

	pub, err := parsePub(out)
	if err != nil {
		return DeployResult{}, err
	}

	return d.buildResult(spec, sids, pub)
}

// buildResult assembles links + subscription from the deployment outputs.
func (d *SSHDeployer) buildResult(spec DeploySpec, sids []string, pub string) (DeployResult, error) {
	res := DeployResult{PublicKey: pub, ShortIDs: sids}
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

// splitHostPort splits "host" or "host:port"; falls back to the given default port.
func splitHostPort(host string, defPort int) (string, string) {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], "]") {
		return host[:i], host[i+1:]
	}
	return host, fmt.Sprintf("%d", defPort)
}
