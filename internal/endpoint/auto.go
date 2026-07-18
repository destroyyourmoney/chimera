package endpoint

import (
	"net"
	"time"

	"chimera/internal/carrier"
)

type Dialer interface {
	DialConnect(host string, port uint16) (net.Conn, error)
}

type UDPDialer interface {
	DialUDPCarrier() (carrier.UDPCarrier, error)
}

type AutoPool struct {
	pool *Pool
}

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

func (a *AutoPool) DialConnect(host string, port uint16) (net.Conn, error) {
	return a.pool.DialRaceConnect(host, port)
}

func (a *AutoPool) DialUDPCarrier() (carrier.UDPCarrier, error) {
	return a.pool.DialUDPCarrier()
}

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

func (a *AutoPool) RemoveEndpoints(servers []string) int {
	return a.pool.RemoveEndpoints(servers)
}

func (a *AutoPool) SetFingerprint(fp string) { a.pool.SetFingerprint(fp) }

func (a *AutoPool) Stats() []Stat { return a.pool.Stats() }

func (a *AutoPool) Pool() *Pool { return a.pool }
