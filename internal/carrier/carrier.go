package carrier

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"chimera/internal/auth"
	"chimera/internal/tunnel"
)

const DialTimeout = 6 * time.Second

type Allowlist interface {
	Allowed(sid []byte) bool
}

type StaticAllowlist [][]byte

func (a StaticAllowlist) Allowed(sid []byte) bool {
	if len(a) == 0 {
		return true
	}
	for _, s := range a {
		if subtle.ConstantTimeCompare(s, sid) == 1 {
			return true
		}
	}
	return false
}

func AllowlistOrAny(allowed Allowlist, sid []byte) bool {
	if allowed == nil {
		return true
	}
	return allowed.Allowed(sid)
}

type TokenVerifier interface {
	VerifyToken(token string, shortIDHex string) bool
}

type Config struct {
	Server       string
	PubB64       string
	SNI          string
	ShortIDHex   string
	Transport    string
	Shaping      bool
	Fp           string
	BandwidthBps uint64

	Token string
}

type QUICServerConfig struct {
	Listen       string
	PrivB64      string
	StealHost    string
	ShortIDs     []string
	BandwidthBps uint64

	Allowlist Allowlist
}

type UDPCarrier interface {
	OpenAssoc(host string, port uint16) (assocID uint16, err error)

	Send(assocID uint16, payload []byte) error

	Receive(ctx context.Context) (assocID uint16, payload []byte, err error)

	Close() error
}

var (
	QUICDialConnect func(cfg Config, host string, port uint16) (net.Conn, error)

	QUICDialConnectRUDP func(cfg Config, host string, port uint16) (net.Conn, error)
	QUICPing            func(cfg Config) error
	QUICServe           func(ctx context.Context, cfg QUICServerConfig) error
	QUICDialUDP         func(cfg Config) (UDPCarrier, error)
)

type SSServerConfig struct {
	Listen        string
	PrivB64       string
	ShortIDs      []string
	Allowlist     Allowlist
	TokenVerifier TokenVerifier
	AuthRate      float64
	AuthBurst     float64
}

var (
	SSDialConnect func(cfg Config, host string, port uint16) (net.Conn, error)
	SSPing        func(cfg Config) error
	SSServe       func(ctx context.Context, cfg SSServerConfig) error
)

var errNoSS = errors.New("carrier: built without Shadowsocks-AEAD support (rebuild with -tags chimera_ss)")

type DoTServerConfig struct {
	Listen        string
	PrivB64       string
	SNI           string
	ShortIDs      []string
	Allowlist     Allowlist
	TokenVerifier TokenVerifier
	AuthRate      float64
	AuthBurst     float64
}

var (
	DoTDialConnect func(cfg Config, host string, port uint16) (net.Conn, error)
	DoTPing        func(cfg Config) error
	DoTServe       func(ctx context.Context, cfg DoTServerConfig) error
)

var errNoDoT = errors.New("carrier: built without DNS-over-TCP support (rebuild with -tags chimera_dot)")

var FingerprintUpdater func(name string)

var errNoQUIC = errors.New("carrier: built without QUIC support (rebuild with -tags chimera_quic)")

func ParseShortID(s string) []byte {
	out := make([]byte, auth.ShortIDLen)
	b, err := hex.DecodeString(s)
	if err == nil {
		copy(out, b)
	}
	return out
}

func DialConnect(cfg Config, host string, port uint16) (net.Conn, error) {
	switch cfg.Transport {
	case "quic":
		if QUICDialConnect == nil {
			return nil, errNoQUIC
		}
		return QUICDialConnect(cfg, host, port)
	case "quic-rudp":
		if QUICDialConnectRUDP == nil {
			return nil, errNoQUIC
		}
		return QUICDialConnectRUDP(cfg, host, port)
	case "ss":
		if SSDialConnect == nil {
			return nil, errNoSS
		}
		return SSDialConnect(cfg, host, port)
	case "dot":
		if DoTDialConnect == nil {
			return nil, errNoDoT
		}
		return DoTDialConnect(cfg, host, port)
	case "auto":
		return DialRace(cfg, host, port)
	}
	conn, sess, err := establish(cfg)
	if err != nil {
		return nil, err
	}
	if err := presentToken(conn, sess, cfg.Token); err != nil {
		conn.Close()
		return nil, err
	}
	if err := sess.WriteConnect(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	ok, err := sess.ReadStatus(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !ok {
		conn.Close()
		return nil, errors.New("carrier: server refused CONNECT (upstream dial failed)")
	}
	return conn, nil
}

func presentToken(conn net.Conn, sess *tunnel.Session, token string) error {
	if token == "" {
		return nil
	}
	if err := sess.WriteAuthToken(conn, token); err != nil {
		return err
	}
	ok, err := sess.ReadStatus(conn)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("carrier: server rejected capability token")
	}
	return nil
}

func DialRace(cfg Config, host string, port uint16) (net.Conn, error) {
	if QUICDialConnect == nil {
		tcpCfg := cfg
		tcpCfg.Transport = "tcp"
		return DialConnect(tcpCfg, host, port)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 2)

	quicCfg := cfg
	quicCfg.Transport = "quic"
	go func() {
		c, err := DialConnect(quicCfg, host, port)
		ch <- result{c, err}
	}()

	tcpCfg := cfg
	tcpCfg.Transport = "tcp"
	go func() {
		c, err := DialConnect(tcpCfg, host, port)
		ch <- result{c, err}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil {
			go func() {

				if r2 := (<-ch); r2.conn != nil {
					r2.conn.Close()
				}
			}()
			return r.conn, nil
		}
		firstErr = r.err
	}
	return nil, fmt.Errorf("carrier: both transports failed: %w", firstErr)
}

func Ping(cfg Config) error {
	switch cfg.Transport {
	case "quic":
		if QUICPing == nil {
			return errNoQUIC
		}
		return QUICPing(cfg)
	case "ss":
		if SSPing == nil {
			return errNoSS
		}
		return SSPing(cfg)
	case "dot":
		if DoTPing == nil {
			return errNoDoT
		}
		return DoTPing(cfg)
	case "auto":
		if QUICPing != nil {
			quicCfg := cfg
			quicCfg.Transport = "quic"
			if err := Ping(quicCfg); err == nil {
				return nil
			}
		}
		tcpCfg := cfg
		tcpCfg.Transport = "tcp"
		return Ping(tcpCfg)
	}
	conn, sess, err := establish(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := presentToken(conn, sess, cfg.Token); err != nil {
		return err
	}
	if err := sess.WritePing(conn); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ok, err := sess.ReadStatus(conn)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("carrier: server did not acknowledge (auth not recognized?)")
	}
	return nil
}
