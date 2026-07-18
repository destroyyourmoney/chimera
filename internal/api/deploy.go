package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"

	"chimera/internal/provision"
)

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

type DeployResultJSON struct {
	PublicKey          string   `json:"publicKey"`
	ShortIDs           []string `json:"shortIds"`
	Links              []string `json:"links"`
	Subscription       string   `json:"subscription"`
	HostKeyFingerprint string   `json:"hostKeyFingerprint"`
}

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

type TeardownSpecJSON struct {
	Host        string `json:"host"`
	SSHPort     int    `json:"sshPort"`
	SSHUser     string `json:"sshUser"`
	SSHPassword string `json:"sshPassword"`
}

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
