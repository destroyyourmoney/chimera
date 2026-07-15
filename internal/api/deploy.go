// deploy.go exposes internal/provision's SSH bootstrap (bare VPS -> running
// CHIMERA server with a fresh Reality keypair) through the same JSON-in/
// JSON-out shape as the rest of this package's UI-facing surface, so the
// desktop/mobile FFI layer never needs its own copy of DeploySpec.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"

	"chimera/internal/provision"
)

// DeploySpecJSON is the wire shape ChimeraDeployServer takes: the SSH login
// for a bare VPS plus the (mostly optional) provision.DeploySpec fields. Only
// password auth is exposed for now, matching the SSH login the rest of the
// app's admin-tunnel flow already asks operators for.
type DeploySpecJSON struct {
	Host         string `json:"host"`
	SSHPort      int    `json:"sshPort"`
	SSHUser      string `json:"sshUser"`
	SSHPassword  string `json:"sshPassword"`
	StealHost    string `json:"stealHost"`
	ServerPort   int    `json:"serverPort"`
	ShortIDCount int    `json:"shortIdCount"`
	Repo         string `json:"repo"`
	Ref          string `json:"ref"`
	Transport    string `json:"transport"`
	SNI          string `json:"sni"`
}

// DeployResultJSON mirrors provision.DeployResult for JSON marshaling, plus
// the SSH host-key fingerprint accepted during this deployment (see
// DeployServerJSON's doc comment) so the UI can surface it for the operator
// to verify out-of-band once, and pin it for subsequent connections.
type DeployResultJSON struct {
	PublicKey          string   `json:"publicKey"`
	ShortIDs           []string `json:"shortIds"`
	Links              []string `json:"links"`
	Subscription       string   `json:"subscription"`
	HostKeyFingerprint string   `json:"hostKeyFingerprint"`
}

// DeployServerJSON dials the given host over SSH, bootstraps a CHIMERA server
// on it (installing Docker if needed, generating the Reality keypair on the
// VPS itself), and returns the resulting DeployResultJSON as JSON. It blocks
// for the whole deployment (installing Docker + building an image can take
// minutes) — callers on a UI thread must run it off the main thread/isolate.
//
// Host-key verification uses trust-on-first-connect: this call has no
// persisted known_hosts store to check against (each call is a fresh SSH
// dial from the UI), so the first key seen for a fresh deployment is
// accepted, mirroring `ssh -o StrictHostKeyChecking=accept-new`, and its
// fingerprint is returned in HostKeyFingerprint rather than silently
// discarded, so the caller can show it once for out-of-band verification
// (e.g. against the fingerprint the VPS host reports in its control panel)
// and pin it for later connections.
func DeployServerJSON(specJSON string) (string, error) {
	var spec DeploySpecJSON
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return "", fmt.Errorf("api: invalid deploy spec: %w", err)
	}
	if spec.Host == "" {
		return "", fmt.Errorf("api: deploy spec: host is required")
	}
	if spec.SSHUser == "" {
		return "", fmt.Errorf("api: deploy spec: sshUser is required")
	}
	sshPort := spec.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}

	var hostKeyFP string
	captureHostKey := ssh.HostKeyCallback(func(_ string, _ net.Addr, key ssh.PublicKey) error {
		hostKeyFP = ssh.FingerprintSHA256(key)
		return nil
	})

	runner, err := provision.NewSSHRunner(
		fmt.Sprintf("%s:%d", spec.Host, sshPort),
		spec.SSHUser,
		[]ssh.AuthMethod{ssh.Password(spec.SSHPassword)},
		captureHostKey,
	)
	if err != nil {
		return "", err
	}

	deployer := &provision.SSHDeployer{Runner: runner}
	res, err := deployer.Deploy(context.Background(), provision.DeploySpec{
		Host:         spec.Host,
		SSHPort:      sshPort,
		StealHost:    spec.StealHost,
		ServerPort:   spec.ServerPort,
		ShortIDCount: spec.ShortIDCount,
		Repo:         spec.Repo,
		Ref:          spec.Ref,
		Transport:    spec.Transport,
		SNI:          spec.SNI,
	})
	if err != nil {
		return "", err
	}

	b, err := json.Marshal(DeployResultJSON{
		PublicKey:          res.PublicKey,
		ShortIDs:           res.ShortIDs,
		Links:              res.Links,
		Subscription:       res.Subscription,
		HostKeyFingerprint: hostKeyFP,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// TeardownSpecJSON is the wire shape ChimeraTeardownServer takes: just enough
// SSH login to reach the VPS -- mirrors DeploySpecJSON's SSH fields (see its
// doc comment on why only password auth is exposed for now).
type TeardownSpecJSON struct {
	Host        string `json:"host"`
	SSHPort     int    `json:"sshPort"`
	SSHUser     string `json:"sshUser"`
	SSHPassword string `json:"sshPassword"`
}

// TeardownServerJSON dials the given host over SSH and removes any
// CHIMERA-managed Docker container(s) there (see provision.SSHDeployer.Teardown),
// so deleting a server from the app doesn't leave it running (and billing)
// on the VPS forever. Returns "" on success; callers should treat this as
// best-effort -- an error here (unreachable host, bad credentials, VPS
// already gone) shouldn't block removing the server from the local list.
func TeardownServerJSON(specJSON string) (string, error) {
	var spec TeardownSpecJSON
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return "", fmt.Errorf("api: invalid teardown spec: %w", err)
	}
	if spec.Host == "" {
		return "", fmt.Errorf("api: teardown spec: host is required")
	}
	if spec.SSHUser == "" {
		return "", fmt.Errorf("api: teardown spec: sshUser is required")
	}
	sshPort := spec.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}

	// Trust-on-first-connect, same rationale as DeployServerJSON: there's no
	// persisted known_hosts store for a call originating fresh from the UI
	// each time.
	runner, err := provision.NewSSHRunner(
		fmt.Sprintf("%s:%d", spec.Host, sshPort),
		spec.SSHUser,
		[]ssh.AuthMethod{ssh.Password(spec.SSHPassword)},
		ssh.HostKeyCallback(func(_ string, _ net.Addr, _ ssh.PublicKey) error { return nil }),
	)
	if err != nil {
		return "", err
	}

	deployer := &provision.SSHDeployer{Runner: runner}
	if err := deployer.Teardown(context.Background()); err != nil {
		return "", err
	}
	return "", nil
}
