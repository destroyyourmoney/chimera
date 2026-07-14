package endpoint

import (
	"net"
	"time"

	"chimera/internal/carrier"
)

// Dialer is satisfied by *Pool (DialConnect) and *AutoPool (racing DialConnect).
// socks.Serve and other callers depend on this interface so they can accept either.
type Dialer interface {
	DialConnect(host string, port uint16) (net.Conn, error)
}

// UDPDialer is the optional capability for opening a UDP-association carrier
// (SOCKS5 UDP ASSOCIATE). Both *Pool and *AutoPool implement it; the SOCKS
// inbound type-asserts for it and rejects UDP ASSOCIATE when it is absent or the
// carrier dial fails (e.g. a TCP-only build).
type UDPDialer interface {
	DialUDPCarrier() (carrier.UDPCarrier, error)
}

// AutoPool wraps a Pool and races QUIC+TCP endpoints concurrently per dial.
// It is constructed by NewAutoPool from a set of server configs; for each config,
// two endpoint entries are created: one QUIC and one TCP. When QUIC is healthy,
// both race and the faster transport wins (mode=auto). When QUIC's health degrades
// (repeated failures → exponential backoff), it is silently demoted: the race only
// fires TCP until QUIC's backoff window expires, then QUIC is automatically promoted
// back into the race.
//
// If QUIC support is not compiled in (carrier.QUICDialConnect == nil), the QUIC
// entries are omitted and AutoPool behaves identically to NewPool with TCP only.
type AutoPool struct {
	pool *Pool
}

// NewAutoPool builds an AutoPool from the provided server configs. Each config
// becomes a QUIC+TCP pair; if QUIC support is absent, only TCP entries are created.
func NewAutoPool(cfgs []carrier.Config) *AutoPool {
	var eps []*endpoint
	for _, c := range cfgs {
		tcpCfg := c
		tcpCfg.Transport = "tcp"
		eps = append(eps, &endpoint{cfg: tcpCfg})

		if carrier.QUICDialConnect != nil {
			quicCfg := c
			quicCfg.Transport = "quic"
			eps = append(eps, &endpoint{cfg: quicCfg})
		}
	}
	return &AutoPool{pool: &Pool{
		eps:     eps,
		dial:    func(c carrier.Config, h string, p uint16) (net.Conn, error) { return carrier.DialConnect(c, h, p) },
		dialUDP: defaultUDPDial,
		now:     time.Now,
	}}
}

// DialConnect races all healthy endpoints concurrently; fastest transport wins.
// Satisfies the Dialer interface so AutoPool can replace *Pool wherever Dialer is accepted.
func (a *AutoPool) DialConnect(host string, port uint16) (net.Conn, error) {
	return a.pool.DialRaceConnect(host, port)
}

// DialUDPCarrier opens a UDP-association carrier through the underlying pool,
// satisfying UDPDialer for the SOCKS5 UDP ASSOCIATE path.
func (a *AutoPool) DialUDPCarrier() (carrier.UDPCarrier, error) {
	return a.pool.DialUDPCarrier()
}

// AddEndpoints mirrors NewAutoPool: each config becomes a TCP (+ QUIC if compiled)
// pair, so auto-provisioned endpoints race transports like the originals.
func (a *AutoPool) AddEndpoints(cfgs []carrier.Config) int {
	var paired []carrier.Config
	for _, c := range cfgs {
		tcpCfg := c
		tcpCfg.Transport = "tcp"
		paired = append(paired, tcpCfg)
		if carrier.QUICDialConnect != nil {
			quicCfg := c
			quicCfg.Transport = "quic"
			paired = append(paired, quicCfg)
		}
	}
	return a.pool.AddEndpoints(paired)
}

// RemoveEndpoints drops all transport variants for the given servers.
func (a *AutoPool) RemoveEndpoints(servers []string) int {
	return a.pool.RemoveEndpoints(servers)
}

// SetFingerprint updates every TCP/QUIC transport variant in the underlying pool.
func (a *AutoPool) SetFingerprint(fp string) { a.pool.SetFingerprint(fp) }

// Stats exposes the underlying endpoint health for telemetry.
func (a *AutoPool) Stats() []Stat { return a.pool.Stats() }

// Pool returns the underlying *Pool so callers can pass it to telemetry.NewMonitor.
func (a *AutoPool) Pool() *Pool { return a.pool }
