// Package chimeramobile is the gomobile-facing facade over internal/api. It is
// the single surface bound into the mobile/FFI clients (Android AAR via
// `gomobile bind`, desktop via the Flutter app's platform channels).
//
// gomobile constraints drive the design: exported methods take and return only
// primitives (string/int/bool/[]byte/error) and the package's own struct
// pointers — no maps, generics, channels, or func parameters cross the boundary.
// Rich state is passed as JSON strings (StateJSON), parsed on the Dart/Kotlin
// side.
//
// Lifecycle (mirrors the platform VPN thread model):
//
//	t, _ := chimeramobile.NewTunnel(subscriptionText, signKeyHex)
//	t.Connect()              // sets up the endpoint pool, returns fast
//	go t.StartFD(fd, 1500)   // blocks until Stop(); run on a background thread
//	... poll t.StateJSON() every ~1s ...
//	t.Stop()
//
// Build for Android:
//
//	gomobile bind -target=android \
//	  -tags "chimera_utls chimera_quic chimera_netstack" \
//	  -o app/android/libs/chimera.aar ./mobile
package chimeramobile

import (
	"context"
	"sync"

	"chimera/internal/api"
)

// Tunnel is a stateful handle around an api.Session for the mobile/FFI clients.
// All methods are safe for concurrent use.
type Tunnel struct {
	sess *api.Session

	mu     sync.Mutex
	cancel context.CancelFunc // cancels the active StartFD/StartSocks runner
}

// NewTunnel builds a Tunnel from a subscription document. When signKeyHex is
// non-empty and the document is signed, the HMAC-SHA256 signature is verified;
// a mismatch returns an error and no Tunnel.
func NewTunnel(subscriptionText, signKeyHex string) (*Tunnel, error) {
	sess, err := api.NewSessionFromSubscription(subscriptionText, signKeyHex)
	if err != nil {
		return nil, err
	}
	return &Tunnel{sess: sess}, nil
}

// NewTunnelFromLink builds a single-endpoint Tunnel from one chimera:// URI —
// the "scan a QR and connect" path. It wraps the link in an unsigned, one-line
// subscription so the same pool machinery applies.
func NewTunnelFromLink(uri string) (*Tunnel, error) {
	doc := "#!chimera-subscription-v1\n" + uri + "\n"
	return NewTunnel(doc, "")
}

// Connect initialises the endpoint pool and verifies reachability. It returns
// quickly; it does NOT start moving packets — call StartFD or StartSocks for
// that. Idempotent.
func (t *Tunnel) Connect() error {
	return t.sess.Connect(context.Background())
}

// StartFD runs the full-device VPN over an OS TUN file descriptor (Android
// VpnService.establish() / desktop helper). It BLOCKS until Stop() is called or
// the device errors, so callers must run it on a background thread. The fd is
// adopted and closed when the runner returns.
func (t *Tunnel) StartFD(fd, mtu int) error {
	ctx := t.beginRun()
	defer t.endRun()
	if mtu <= 0 {
		mtu = 1500
	}
	return t.sess.ConnectTUN(ctx, fd, mtu)
}

// StartSocks runs the TUN-less SOCKS5 fallback on listen (e.g.
// "127.0.0.1:1080"). It BLOCKS until Stop(); run on a background thread.
func (t *Tunnel) StartSocks(listen string) error {
	ctx := t.beginRun()
	defer t.endRun()
	if listen == "" {
		listen = "127.0.0.1:1080"
	}
	return t.sess.RunSOCKS(ctx, listen)
}

// Stop cancels the active runner (StartFD/StartSocks) and tears down the
// session. After Stop the Tunnel can be reused by calling Connect again.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.mu.Unlock()
	t.sess.Disconnect()
}

// StateJSON returns the current session state as a JSON string (see
// api.StateSnapshot). Poll this from the UI; it never blocks.
func (t *Tunnel) StateJSON() string { return t.sess.StateJSON() }

// beginRun installs a fresh cancellable context for a blocking runner,
// cancelling any previous one.
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

// ParseLink parses a chimera:// URI and returns its fields as a JSON string, for
// the "add server" / QR-scan UI flow.
func ParseLink(uri string) (string, error) { return api.ParseLinkJSON(uri) }

// DeployServer bootstraps a CHIMERA server on a bare VPS over SSH (installing
// Docker, generating the Reality keypair on the box itself) from a JSON
// api.DeploySpecJSON and returns a JSON api.DeployResultJSON — the "I don't
// have a chimera:// link yet, I have a fresh server" UI flow. Blocks for the
// whole deployment; run on a background thread like StartFD/StartSocks.
func DeployServer(specJSON string) (string, error) { return api.DeployServerJSON(specJSON) }

// TeardownServer removes any CHIMERA-managed Docker container(s) from a VPS
// over SSH (from a JSON api.TeardownSpecJSON) -- the counterpart to
// DeployServer, used when the user deletes a server from the app. Blocks for
// the SSH round-trip; run on a background thread like DeployServer.
func TeardownServer(specJSON string) (string, error) { return api.TeardownServerJSON(specJSON) }
