package chimeramobile

import (
	"context"
	"sync"

	"chimera/internal/api"
)

type Tunnel struct {
	sess *api.Session

	mu     sync.Mutex
	cancel context.CancelFunc
}

func NewTunnel(subscriptionText, signKeyHex string) (*Tunnel, error) {
	sess, err := api.NewSessionFromSubscription(subscriptionText, signKeyHex)
	if err != nil {
		return nil, err
	}
	return &Tunnel{sess: sess}, nil
}

func NewTunnelFromLink(uri string) (*Tunnel, error) {
	doc := "#!chimera-subscription-v1\n" + uri + "\n"
	return NewTunnel(doc, "")
}

func (t *Tunnel) Connect() error {
	return t.sess.Connect(context.Background())
}

func (t *Tunnel) StartFD(fd, mtu int) error {
	ctx := t.beginRun()
	defer t.endRun()
	if mtu <= 0 {
		mtu = 1500
	}
	return t.sess.ConnectTUN(ctx, fd, mtu)
}

func (t *Tunnel) StartSocks(listen string) error {
	ctx := t.beginRun()
	defer t.endRun()
	if listen == "" {
		listen = "127.0.0.1:1080"
	}
	return t.sess.RunSOCKS(ctx, listen)
}

func (t *Tunnel) Stop() {
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.mu.Unlock()
	t.sess.Disconnect()
}

func (t *Tunnel) StateJSON() string { return t.sess.StateJSON() }

func (t *Tunnel) beginRun() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
	}
	t.cancel = cancel
	t.mu.Unlock()
	return ctx
}

func (t *Tunnel) endRun() {
	t.mu.Lock()
	t.cancel = nil
	t.mu.Unlock()
}

func ParseLink(uri string) (string, error) { return api.ParseLinkJSON(uri) }

func DeployServer(specJSON string) (string, error) { return api.DeployServerJSON(specJSON) }

func TeardownServer(specJSON string) (string, error) { return api.TeardownServerJSON(specJSON) }
