package provision

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHRunner is a CommandRunner that executes scripts on a remote host over SSH.
// Host-key verification is mandatory: the caller supplies the HostKeyCallback
// (e.g. knownhosts.New(...) or a TOFU callback that pins on first sight). We do
// not default to InsecureIgnoreHostKey.
type SSHRunner struct {
	Addr    string // "host:port"
	User    string
	Auth    []ssh.AuthMethod
	HostKey ssh.HostKeyCallback
	Timeout time.Duration // dial timeout; default 15s
}

// NewSSHRunner builds an SSHRunner. A nil hostKey is rejected — verification is
// required. Pass knownhosts.New(path) or a pinning callback.
func NewSSHRunner(addr, user string, auth []ssh.AuthMethod, hostKey ssh.HostKeyCallback) (*SSHRunner, error) {
	if hostKey == nil {
		return nil, fmt.Errorf("provision: host-key callback is required (refusing to skip verification)")
	}
	return &SSHRunner{Addr: addr, User: user, Auth: auth, HostKey: hostKey}, nil
}

// Run opens a session, pipes the script to a login shell, and returns stdout.
// stderr is folded into the error on non-zero exit so failures are diagnosable.
func (r *SSHRunner) Run(ctx context.Context, script string) (string, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	cfg := &ssh.ClientConfig{
		User:            r.User,
		Auth:            r.Auth,
		HostKeyCallback: r.HostKey,
		Timeout:         timeout,
	}

	d := net.Dialer{Timeout: timeout}
	netConn, err := d.DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return "", fmt.Errorf("provision: dial %s: %w", r.Addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, r.Addr, cfg)
	if err != nil {
		netConn.Close()
		return "", fmt.Errorf("provision: ssh handshake %s: %w", r.Addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("provision: ssh session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	sess.Stdin = bytes.NewReader([]byte(script))

	// Cancel the session if the context is cancelled mid-run.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			sess.Signal(ssh.SIGKILL)
			sess.Close()
		case <-done:
		}
	}()

	// "sh -s" reads the script from stdin — no temp file on the VPS.
	if err := sess.Run("sh -s"); err != nil {
		return stdout.String(), fmt.Errorf("provision: remote script: %w; stderr: %s", err, stderr.String())
	}
	return stdout.String(), nil
}
