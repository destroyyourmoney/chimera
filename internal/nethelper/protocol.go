package nethelper

const Port = 47821

const (
	CmdPing  = "ping"
	CmdStart = "start"
	CmdStop  = "stop"
)

const (
	ModeDNSLeakGuard = "dnsLeakGuard"
	ModeKillswitch   = "killswitch"
)

type Request struct {
	Cmd    string   `json:"cmd"`
	Token  string   `json:"token"`
	Server string   `json:"server,omitempty"`
	Pbk    string   `json:"pbk,omitempty"`
	Sni    string   `json:"sni,omitempty"`
	Sid    string   `json:"sid,omitempty"`
	Mode   string   `json:"mode,omitempty"`
	DNS    []string `json:"dns,omitempty"`

	Transport string `json:"transport,omitempty"`

	CapabilityToken string `json:"capabilityToken,omitempty"`
}

const (
	StateIdle    = "idle"
	StateRunning = "running"
)

type TunnelStats struct {
	BytesUp   uint64
	BytesDown uint64
	Server    string
	Transport string
}

type Response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	State     string `json:"state,omitempty"`
	BytesUp   uint64 `json:"bytesUp,omitempty"`
	BytesDown uint64 `json:"bytesDown,omitempty"`
	Server    string `json:"server,omitempty"`
	Transport string `json:"transport,omitempty"`
}
