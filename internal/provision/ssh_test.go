package provision

import (
	"context"
	"strings"
	"testing"

	"chimera/internal/link"
	"chimera/internal/subscription"
)

// fakeRunner records the script it received and returns a canned output.
type fakeRunner struct {
	gotScript string
	out       string
	err       error
}

func (f *fakeRunner) Run(_ context.Context, script string) (string, error) {
	f.gotScript = script
	return f.out, f.err
}

func TestDeploy_BuildsLinkAndSignedSubscription(t *testing.T) {
	fr := &fakeRunner{out: "some build noise...\nCHIMERA_PUB=ABC123pub\ndone\n"}
	d := &SSHDeployer{Runner: fr, SignKey: []byte("operatorkey")}

	res, err := d.Deploy(context.Background(), DeploySpec{
		Host:      "203.0.113.7",
		StealHost: "www.microsoft.com:443",
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if res.PublicKey != "ABC123pub" {
		t.Fatalf("pub = %q", res.PublicKey)
	}
	if len(res.Links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(res.Links))
	}

	// The link must round-trip and carry the deployed pub/host/sid.
	p, err := link.Parse(res.Links[0])
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	if p.Host != "203.0.113.7" || p.Port != "443" || p.Pbk != "ABC123pub" {
		t.Fatalf("link fields wrong: %+v", p)
	}
	if p.Sni != "www.microsoft.com" {
		t.Fatalf("SNI not derived from steal-host: %q", p.Sni)
	}

	// The subscription must be valid and verify under the operator key.
	if !strings.HasPrefix(res.Subscription, "#!chimera-subscription-v1\n# sig: ") {
		t.Fatalf("subscription not signed:\n%s", res.Subscription)
	}
	if _, err := subscription.Parse(strings.NewReader(res.Subscription), []byte("operatorkey")); err != nil {
		t.Fatalf("signed subscription failed verification: %v", err)
	}
}

func TestDeploy_ScriptKeepsPrivateKeyServerSide(t *testing.T) {
	fr := &fakeRunner{out: "CHIMERA_PUB=pub\n"}
	d := &SSHDeployer{Runner: fr}
	if _, err := d.Deploy(context.Background(), DeploySpec{Host: "1.2.3.4"}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	s := fr.gotScript
	// PRIV must only ever live in a shell var; it must never be echoed back.
	if strings.Contains(s, "echo \"CHIMERA_PUB=$PRIV") {
		t.Fatal("script leaks private key")
	}
	if !strings.Contains(s, pubMarker+"$PUB") {
		t.Fatal("script does not emit public key marker")
	}
	// Build must use the stealth+QUIC tags.
	if !strings.Contains(s, "TAGS='"+serverBuildTags+"'") {
		t.Fatalf("script missing server build tags:\n%s", s)
	}
	// Both TCP and UDP (QUIC) ports must be published.
	if !strings.Contains(s, "443:443/tcp") || !strings.Contains(s, "443:443/udp") {
		t.Fatal("script does not publish both tcp and udp")
	}
}

func TestDeploy_RejectsShellInjection(t *testing.T) {
	d := &SSHDeployer{Runner: &fakeRunner{out: "CHIMERA_PUB=pub\n"}}
	_, err := d.Deploy(context.Background(), DeploySpec{
		Host: "1.2.3.4",
		Repo: "https://x/'; rm -rf / #.git",
	})
	if err == nil {
		t.Fatal("expected rejection of repo with single quote")
	}
}

func TestDeploy_ErrorsWhenNoPubMarker(t *testing.T) {
	d := &SSHDeployer{Runner: &fakeRunner{out: "build failed, no marker\n"}}
	if _, err := d.Deploy(context.Background(), DeploySpec{Host: "1.2.3.4"}); err == nil {
		t.Fatal("expected error when remote output lacks the pub marker")
	}
}

func TestDeploy_MultipleShortIDs(t *testing.T) {
	d := &SSHDeployer{Runner: &fakeRunner{out: "CHIMERA_PUB=pub\n"}}
	res, err := d.Deploy(context.Background(), DeploySpec{Host: "1.2.3.4", ShortIDCount: 3})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(res.ShortIDs) != 3 {
		t.Fatalf("expected 3 short IDs, got %d", len(res.ShortIDs))
	}
	if len(res.Links) != 3 {
		t.Fatalf("expected 3 links, got %d", len(res.Links))
	}
}

func TestNewSSHRunner_RequiresHostKey(t *testing.T) {
	if _, err := NewSSHRunner("h:22", "root", nil, nil); err == nil {
		t.Fatal("expected error when host-key callback is nil")
	}
}

func TestDeploy_LabelsContainerAndSelfHealsPortConflict(t *testing.T) {
	fr := &fakeRunner{out: "CHIMERA_PUB=pub\n"}
	d := &SSHDeployer{Runner: fr}
	if _, err := d.Deploy(context.Background(), DeploySpec{Host: "1.2.3.4"}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	s := fr.gotScript
	if !strings.Contains(s, "--label 'io.chimera.managed=true'") {
		t.Fatalf("script does not label the container:\n%s", s)
	}
	// The port pre-check must attempt a label+publish-scoped self-heal
	// before giving up with portInUseMarker -- see script.go's step 0 doc
	// comment on why (redeploying to a host whose own prior CHIMERA
	// container still holds the port must not be treated as a conflict).
	if !strings.Contains(s, "label=io.chimera.managed=true") ||
		!strings.Contains(s, "publish=443") {
		t.Fatalf("script does not self-heal a stale CHIMERA container on the port:\n%s", s)
	}
	if !strings.Contains(s, portInUseMarker) {
		t.Fatalf("script dropped the port-in-use error path entirely:\n%s", s)
	}
}

func TestTeardown_RemovesLabeledContainers(t *testing.T) {
	fr := &fakeRunner{}
	d := &SSHDeployer{Runner: fr}
	if err := d.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	s := fr.gotScript
	if !strings.Contains(s, "label=io.chimera.managed=true") {
		t.Fatalf("teardown script does not filter by the CHIMERA label:\n%s", s)
	}
	if !strings.Contains(s, "docker rm -f $IDS") {
		t.Fatalf("teardown script does not remove the matched containers:\n%s", s)
	}
}

func TestTeardown_NilRunnerErrors(t *testing.T) {
	d := &SSHDeployer{}
	if err := d.Teardown(context.Background()); err == nil {
		t.Fatal("expected error with a nil Runner")
	}
}
