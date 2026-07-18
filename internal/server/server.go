package server

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"chimera/internal/auth"
	"chimera/internal/carrier"
	"chimera/internal/clienthello"
	"chimera/internal/keys"
	"chimera/internal/preconnect"
	"chimera/internal/ratelimit"
	"chimera/internal/serve"
	"chimera/internal/tunnel"
	"chimera/internal/vision"
)

const (
	DefaultAuthRate  = 50.0
	DefaultAuthBurst = 100.0
	cleanupInterval  = 2 * time.Minute
	cleanupIdle      = 5 * time.Minute
)

type Config struct {
	Listen    string
	StealHost string
	PrivB64   string
	ShortIDs  []string
	AuthRate  float64
	AuthBurst float64

	Allowlist carrier.Allowlist

	TokenVerifier carrier.TokenVerifier
}

type server struct {
	priv          *ecdh.PrivateKey
	serverPub     []byte
	stealHost     string
	allowed       carrier.Allowlist
	tokenVerifier carrier.TokenVerifier
	limiter       *ratelimit.Limiter
	preconn       *preconnect.Pool
}

func Run(ctx context.Context, cfg Config) error {
	priv, err := keys.DecodePrivate(cfg.PrivB64)
	if err != nil {
		return err
	}
	allowed := resolveAllowlist(cfg)

	rate, burst := cfg.AuthRate, cfg.AuthBurst
	if rate <= 0 {
		rate, burst = DefaultAuthRate, DefaultAuthBurst
	}
	s := &server{
		priv:          priv,
		serverPub:     priv.PublicKey().Bytes(),
		stealHost:     cfg.StealHost,
		allowed:       allowed,
		tokenVerifier: cfg.TokenVerifier,
		limiter:       ratelimit.New(rate, burst),
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	slog.Info("carrier up", "listen", cfg.Listen, "steal_host", cfg.StealHost, "short_ids", len(cfg.ShortIDs), "auth_rate", rate)
	return s.serve(ctx, ln)
}

func Serve(ctx context.Context, ln net.Listener, cfg Config) error {
	priv, err := keys.DecodePrivate(cfg.PrivB64)
	if err != nil {
		return err
	}
	allowed := resolveAllowlist(cfg)
	rate, burst := cfg.AuthRate, cfg.AuthBurst
	if rate <= 0 {
		rate, burst = DefaultAuthRate, DefaultAuthBurst
	}
	s := &server{
		priv:          priv,
		serverPub:     priv.PublicKey().Bytes(),
		stealHost:     cfg.StealHost,
		allowed:       allowed,
		tokenVerifier: cfg.TokenVerifier,
		limiter:       ratelimit.New(rate, burst),
	}
	return s.serve(ctx, ln)
}

func (s *server) serve(ctx context.Context, ln net.Listener) error {
	s.preconn = preconnect.New(ctx, s.stealHost, 0)
	go s.janitor(ctx)
	err := serve.Loop(ctx, ln, serve.DefaultDrain, s.handle)
	slog.Info("carrier stopped")
	return err
}

func (s *server) janitor(ctx context.Context) {
	t := time.NewTicker(cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.limiter.Cleanup(cleanupIdle)
		}
	}
}

func resolveAllowlist(cfg Config) carrier.Allowlist {
	if cfg.Allowlist != nil {
		return cfg.Allowlist
	}
	ids := make(carrier.StaticAllowlist, 0, len(cfg.ShortIDs))
	for _, s := range cfg.ShortIDs {
		ids = append(ids, carrier.ParseShortID(s))
	}
	return ids
}

func (s *server) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)

	raw, err := readRecord(br)
	if err != nil {
		return
	}

	var sharedSecret, shortID []byte
	if s.limiter.Allow(peerIP(c)) {
		sharedSecret, shortID = s.authenticate(raw)
	}

	if sharedSecret != nil {
		rw, err := s.authedTransport(c, br, raw, sharedSecret)
		if err != nil {
			return
		}
		defer rw.Close()
		serveTunnel(rw, tunnel.ServerSession(sharedSecret), s.checkToken(shortID))
		return
	}
	spliceConn(c, br, raw, s.preconn)
}

func (s *server) authenticate(raw []byte) (sharedSecret, shortID []byte) {
	sid, xpub, perr := clienthello.Parse(raw)
	if perr != nil || len(xpub) != 32 || len(sid) < auth.TagLen {
		return nil, nil
	}
	pub, kerr := ecdh.X25519().NewPublicKey(xpub)
	if kerr != nil {
		return nil, nil
	}
	ss, derr := s.priv.ECDH(pub)
	if derr != nil {
		return nil, nil
	}
	recovered, ok := auth.Open(ss, xpub, s.serverPub, sid[:auth.TagLen])
	if !ok {
		return nil, nil
	}
	if s.tokenVerifier == nil && !carrier.AllowlistOrAny(s.allowed, recovered) {
		return nil, nil
	}
	return ss, recovered
}

func (s *server) checkToken(shortID []byte) func(token string) bool {
	if s.tokenVerifier == nil {
		return nil
	}
	shortIDHex := hex.EncodeToString(shortID)
	return func(token string) bool {
		return s.tokenVerifier.VerifyToken(token, shortIDHex)
	}
}

func peerIP(c net.Conn) string {
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return host
	}
	return c.RemoteAddr().String()
}

func serveTunnel(rw io.ReadWriteCloser, sess *tunnel.Session, verifyToken func(token string) bool) {
	if verifyToken != nil {
		token, err := sess.ReadAuthToken(rw)
		if err != nil {
			return
		}
		ok := verifyToken(token)
		if err := sess.WriteStatus(rw, ok); err != nil || !ok {
			return
		}
	}
	cmd, host, port, err := sess.ReadRequest(rw)
	if err != nil {
		return
	}
	if cmd == tunnel.CmdPing {
		_ = sess.WriteStatus(rw, true)
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = sess.WriteStatus(rw, false)
		return
	}
	defer target.Close()
	if err := sess.WriteStatus(rw, true); err != nil {
		return
	}
	vision.Splice(rw, target)
}

func spliceConn(c net.Conn, br *bufio.Reader, replay []byte, pool *preconnect.Pool) {
	ctx := context.Background()
	backend, err := pool.Get(ctx)
	if err != nil {
		return
	}
	defer backend.Close()
	if _, err := backend.Write(replay); err != nil {
		return
	}
	go func() { _, _ = io.Copy(backend, br) }()
	_, _ = io.Copy(c, backend)
}

func splice(c net.Conn, br *bufio.Reader, replay []byte, stealHost string) {
	backend, err := net.Dial("tcp", stealHost)
	if err != nil {
		return
	}
	defer backend.Close()
	if _, err := backend.Write(replay); err != nil {
		return
	}
	go func() { _, _ = io.Copy(backend, br) }()
	_, _ = io.Copy(c, backend)
}

func readRecord(br *bufio.Reader) ([]byte, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return nil, err
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	full := make([]byte, 5+recLen)
	if _, err := io.ReadFull(br, full); err != nil {
		return nil, err
	}
	return full, nil
}
