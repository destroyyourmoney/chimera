package provision

import (
	"context"
	"strings"
	"testing"

	"chimera/internal/link"
	"chimera/internal/subscription"
)

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

	if strings.Contains(s, "echo \"CHIMERA_PUB=$PRIV") {
		t.Fatal("script leaks private key")
	}
	if !strings.Contains(s, pubMarker+"$PUB") {
		t.Fatal("script does not emit public key marker")
	}

	if !strings.Contains(s, "TAGS='"+serverBuildTags+"'") {
		t.Fatalf("script missing server build tags:\n%s", s)
	}

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

func TestDeploy_ExtraListenersLaunchOneContainerEach(t *testing.T) {
	fr := &fakeRunner{out: "CHIMERA_PUB=pub\n"}
	d := &SSHDeployer{Runner: fr}
	res, err := d.Deploy(context.Background(), DeploySpec{
		Host: "1.2.3.4",
		ExtraListeners: []ListenerSpec{
			{Transport: "quic", Port: 8443},
			{Transport: "ss", Port: 8444},
			{Transport: "dot", Port: 8445},
		},
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	if len(res.Listeners) != 4 {
		t.Fatalf("expected 4 listeners (reality + 3 extras), got %+v", res.Listeners)
	}
	want := []DeployedListener{
		{Transport: "reality", Port: 443},
		{Transport: "quic", Port: 8443},
		{Transport: "ss", Port: 8444},
		{Transport: "dot", Port: 8445},
	}
	for i, w := range want {
		if res.Listeners[i] != w {
			t.Fatalf("Listeners[%d] = %+v, want %+v", i, res.Listeners[i], w)
		}
	}

	s := fr.gotScript

	for _, tc := range []struct{ container, transport, port string }{
		{"chimera-server-quic", "quic", "8443"},
		{"chimera-server-ss", "ss", "8444"},
		{"chimera-server-dot", "dot", "8445"},
	} {
		if !strings.Contains(s, "--name '"+tc.container+"'") {
			t.Errorf("script missing container %q:\n%s", tc.container, s)
		}
		if !strings.Contains(s, "-transport '"+tc.transport+"'") {
			t.Errorf("script missing -transport %q:\n%s", tc.transport, s)
		}
		if !strings.Contains(s, tc.port+":"+tc.port+"/tcp") {
			t.Errorf("script missing port mapping for %s:\n%s", tc.port, s)
		}
	}

	if strings.Contains(s, "':' server -listen :443 -transport") {
		t.Fatal("primary listener should not pass -transport")
	}

	if strings.Count(s, "docker run --rm") != 1 {
		t.Fatalf("expected exactly one keygen invocation, script:\n%s", s)
	}
	if strings.Count(s, "-priv \"$PRIV\"") != 4 {
		t.Fatalf("expected all 4 listener containers to share $PRIV, script:\n%s", s)
	}
}

func TestDeploy_RejectsUnknownExtraTransport(t *testing.T) {
	d := &SSHDeployer{Runner: &fakeRunner{out: "CHIMERA_PUB=pub\n"}}
	_, err := d.Deploy(context.Background(), DeploySpec{
		Host:           "1.2.3.4",
		ExtraListeners: []ListenerSpec{{Transport: "wireguard", Port: 51820}},
	})
	if err == nil {
		t.Fatal("expected rejection of an unknown transport")
	}
}

func TestDeploy_RejectsRealityAsExtraListener(t *testing.T) {
	d := &SSHDeployer{Runner: &fakeRunner{out: "CHIMERA_PUB=pub\n"}}
	_, err := d.Deploy(context.Background(), DeploySpec{
		Host:           "1.2.3.4",
		ExtraListeners: []ListenerSpec{{Transport: "reality", Port: 8443}},
	})
	if err == nil {
		t.Fatal("expected rejection of Reality as an extra listener (it's always the primary)")
	}
}

func TestDeploy_RejectsDuplicatePorts(t *testing.T) {
	d := &SSHDeployer{Runner: &fakeRunner{out: "CHIMERA_PUB=pub\n"}}
	_, err := d.Deploy(context.Background(), DeploySpec{
		Host: "1.2.3.4",
		ExtraListeners: []ListenerSpec{
			{Transport: "quic", Port: 443},
		},
	})
	if err == nil {
		t.Fatal("expected rejection of a port collision with the primary listener")
	}

	_, err = d.Deploy(context.Background(), DeploySpec{
		Host: "1.2.3.4",
		ExtraListeners: []ListenerSpec{
			{Transport: "quic", Port: 8443},
			{Transport: "ss", Port: 8443},
		},
	})
	if err == nil {
		t.Fatal("expected rejection of a port collision between two extra listeners")
	}
}

func TestDeploy_RejectsInvalidExtraPort(t *testing.T) {
	d := &SSHDeployer{Runner: &fakeRunner{out: "CHIMERA_PUB=pub\n"}}
	_, err := d.Deploy(context.Background(), DeploySpec{
		Host:           "1.2.3.4",
		ExtraListeners: []ListenerSpec{{Transport: "quic", Port: 0}},
	})
	if err == nil {
		t.Fatal("expected rejection of an invalid port")
	}
}

func TestDeploy_NoExtraListenersMatchesPreExistingScriptExactly(t *testing.T) {

	fr := &fakeRunner{out: "CHIMERA_PUB=pub\n"}
	d := &SSHDeployer{Runner: fr}
	if _, err := d.Deploy(context.Background(), DeploySpec{Host: "1.2.3.4"}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	s := fr.gotScript
	if strings.Count(s, "docker run -d --name") != 1 {
		t.Fatalf("expected exactly one docker run with no ExtraListeners, script:\n%s", s)
	}
	if !strings.Contains(s, "server -listen :443 -steal-host") {
		t.Fatalf("primary listener command shape changed:\n%s", s)
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
