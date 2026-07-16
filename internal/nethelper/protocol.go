// Package nethelper defines the local IPC protocol between the unprivileged
// tray app and chimera-helper, the persistent Windows service that owns the
// actual elevated network setup (TUN device, routes, DNS, firewall). The app
// sends one newline-delimited JSON Request per TCP connection to
// 127.0.0.1:Port and reads back one newline-delimited JSON Response; the
// connection is then closed (request/response, not a persistent session).
//
// Transport is loopback TCP rather than a named pipe: it needs no extra
// dependency (Dart's dart:io has full TCP support; a Windows named pipe
// would need either cgo/FFI or a third-party Dart plugin) and is simple to
// reason about. Since 127.0.0.1 is reachable by any local process, the
// Request.Token shared secret is what actually restricts who can command
// the service -- see token.go for how it's generated and shared.
package nethelper

// Port is the fixed loopback TCP port chimera-helper listens on. Fixed
// rather than OS-assigned because the client has no other channel to learn
// an assigned port; if this port is ever unavailable to bind, the service
// logs and exits (see cmd/chimera-helper) rather than falling back silently.
const Port = 47821

// Cmd values accepted in Request.Cmd.
const (
	CmdPing  = "ping"
	CmdStart = "start"
	CmdStop  = "stop"
)

// Mode mirrors settings_store.dart's NetworkProtectionMode, minus "off"
// (off is expressed by calling Stop, not Start with a mode).
const (
	ModeDNSLeakGuard = "dnsLeakGuard"
	ModeKillswitch   = "killswitch"
)

// Request is one command sent to chimera-helper. Server/Pbk are required for
// CmdStart; Sni/Sid/DNS are optional and fall back to chimera.exe tun's own
// defaults when empty/absent.
type Request struct {
	Cmd    string   `json:"cmd"`
	Token  string   `json:"token"`
	Server string   `json:"server,omitempty"`
	Pbk    string   `json:"pbk,omitempty"`
	Sni    string   `json:"sni,omitempty"`
	Sid    string   `json:"sid,omitempty"`
	Mode   string   `json:"mode,omitempty"`
	DNS    []string `json:"dns,omitempty"`

	// Transport is the anti-censorship transport to force on chimera.exe
	// tun's carrier dialer ("auto", "quic", or "tcp" -- matches the
	// chimera:// link's own Mode field, see internal/link.Profile.Mode).
	// Empty defers to chimera.exe tun's own "auto" default.
	Transport string `json:"transport,omitempty"`

	// CapabilityToken is the control-plane capability token (ROADMAP2 §1) to
	// forward to chimera.exe tun's own -token flag -- distinct from Token
	// above, which authenticates the app to chimera-helper itself, not
	// chimera-helper to the CHIMERA server. Empty for -auth-mode useracl
	// servers/legacy BYO links, which never expect one.
	CapabilityToken string `json:"capabilityToken,omitempty"`
}

// State values reported in Response.State.
const (
	StateIdle    = "idle"    // no tunnel running
	StateRunning = "running" // chimera.exe tun child is alive
)

// TunnelStats is the live throughput/identity snapshot of a running tunnel,
// sourced from the chimera.exe tun child's own status file (see
// cmd/chimera-helper's procRunner.Stats and cmd/chimera/tun_on.go's
// runStatusWriter) -- the tray has no other channel into that process, so
// this is how it learns real byte counts instead of guessing from an
// unrelated SOCKS session.
type TunnelStats struct {
	BytesUp   uint64
	BytesDown uint64
	Server    string
	Transport string
}

// Response is chimera-helper's reply to a Request.
type Response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	State     string `json:"state,omitempty"`
	BytesUp   uint64 `json:"bytesUp,omitempty"`
	BytesDown uint64 `json:"bytesDown,omitempty"`
	Server    string `json:"server,omitempty"`
	Transport string `json:"transport,omitempty"`
}
