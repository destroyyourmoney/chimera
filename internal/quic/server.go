//go:build chimera_quic

package quic

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	h3 "github.com/quic-go/quic-go/http3"

	"chimera/internal/auth"
	"chimera/internal/carrier"
	"chimera/internal/keys"
	"chimera/internal/tunnel"
	"chimera/internal/vision"
)

const authReadTimeout = 10 * time.Second

func Run(ctx context.Context, cfg carrier.QUICServerConfig) error {
	priv, err := keys.DecodePrivate(cfg.PrivB64)
	if err != nil {
		return err
	}
	serverPub := priv.PublicKey().Bytes()
	allowed := cfg.Allowlist
	if allowed == nil {
		ids := make(carrier.StaticAllowlist, 0, len(cfg.ShortIDs))
		for _, s := range cfg.ShortIDs {
			ids = append(ids, carrier.ParseShortID(s))
		}
		allowed = ids
	}

	tlsConf, err := serverTLS()
	if err != nil {
		return err
	}
	ln, err := quic.ListenAddrEarly(cfg.Listen, tlsConf, quicConfig(cfg.BandwidthBps))
	if err != nil {
		return err
	}
	slog.Info("quic carrier up", "listen", cfg.Listen, "short_ids", len(cfg.ShortIDs), "steal_host", cfg.StealHost)
	return serveListenerWithFallback(ctx, ln, priv, serverPub, allowed, cfg.StealHost)
}

func serveListener(ctx context.Context, ln quicListener, priv *ecdh.PrivateKey, serverPub []byte, allowed carrier.Allowlist) error {
	return serveListenerWithFallback(ctx, ln, priv, serverPub, allowed, "")
}

func serveListenerWithFallback(ctx context.Context, ln quicListener, priv *ecdh.PrivateKey, serverPub []byte, allowed carrier.Allowlist, stealHost string) error {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				slog.Info("quic carrier stopped")
				return nil
			}
			return err
		}
		go serveConn(ctx, conn, priv, serverPub, allowed, stealHost)
	}
}

func serveConn(ctx context.Context, conn *quic.Conn, priv *ecdh.PrivateKey, serverPub []byte, allowed carrier.Allowlist, stealHost string) {
	if stealHost != "" {
		if serveH3ProbeIfPresent(ctx, conn, stealHost) {
			return
		}
	}
	defer conn.CloseWithError(0, "")
	mux := newDatagramMux(ctx, conn)
	defer mux.Close()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveStream(stream, priv, serverPub, allowed, stealHost, mux)
	}
}

func serveH3ProbeIfPresent(ctx context.Context, conn *quic.Conn, stealHost string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	firstUni, err := conn.AcceptUniStream(probeCtx)
	cancel()
	if err != nil {
		return false
	}
	go serveH3FallbackConn(ctx, conn, firstUni, stealHost)
	return true
}

func serveH3FallbackConn(ctx context.Context, conn *quic.Conn, firstUni *quic.ReceiveStream, stealHost string) {
	srv := &h3.Server{
		Handler:     h3FallbackHandler(stealHost),
		IdleTimeout: idleTimeout,
		Logger:      slog.Default(),
	}
	hconn, err := srv.NewRawServerConn(conn)
	if err != nil {
		slog.Debug("h3 fallback: raw conn failed", "target", stealHost, "err", err)
		return
	}

	go func() {
		hconn.HandleUnidirectionalStream(firstUni)
		for {
			str, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go hconn.HandleUnidirectionalStream(str)
		}
	}()
	for {
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go hconn.HandleRequestStream(str)
	}
}

func h3FallbackHandler(stealHost string) http.Handler {
	host := stealHost
	if h, _, err := net.SplitHostPort(stealHost); err == nil {
		host = h
	}
	rt := &h3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{h3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  idleTimeout,
			KeepAlivePeriod: keepAlive,
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := r.Clone(r.Context())
		out.URL.Scheme = "https"
		out.URL.Host = stealHost
		out.RequestURI = ""
		if out.Host == "" || strings.Contains(out.Host, ":") {
			out.Host = host
		}
		resp, err := rt.RoundTrip(out)
		if err != nil {
			slog.Debug("h3 fallback: upstream failed", "target", stealHost, "err", err)
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func serveStream(stream *quic.Stream, priv *ecdh.PrivateKey, serverPub []byte, allowed carrier.Allowlist, stealHost string, mux *datagramMux) {
	defer stream.Close()

	preface := make([]byte, prefaceLen)
	_ = stream.SetReadDeadline(time.Now().Add(authReadTimeout))
	if _, err := io.ReadFull(stream, preface); err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	ephPub := preface[:32]
	tag := preface[32:]
	pub, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		spliceToStealHost(stream, preface, stealHost)
		return
	}
	ss, err := priv.ECDH(pub)
	if err != nil {
		spliceToStealHost(stream, preface, stealHost)
		return
	}
	shortID, ok := auth.Open(ss, ephPub, serverPub, tag)
	if !ok || !shortIDAllowed(allowed, shortID) {
		spliceToStealHost(stream, preface, stealHost)
		return
	}
	serveTunnel(stream, tunnel.ServerSession(ss), mux)
}

func spliceToStealHost(stream io.ReadWriter, preface []byte, stealHost string) {
	if stealHost == "" {
		return
	}
	backend, err := net.DialTimeout("tcp", stealHost, 5*time.Second)
	if err != nil {
		slog.Debug("quic fallback: dial steal-host failed", "target", stealHost, "err", err)
		return
	}
	defer backend.Close()

	if _, err := backend.Write(preface); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, stream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(stream, backend); done <- struct{}{} }()
	<-done
}

func serveTunnel(rw io.ReadWriteCloser, sess *tunnel.Session, mux *datagramMux) {
	cmd, host, port, err := sess.ReadRequest(rw)
	if err != nil {
		return
	}
	switch cmd {
	case tunnel.CmdPing:
		_ = sess.WriteStatus(rw, true)
	case tunnel.CmdConnect:
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
	case tunnel.CmdConnectRUDP:
		serveRUDPConnect(mux.conn, sess, rw, host, port)
	case tunnel.CmdUDPAssoc:
		mux.ensureDispatch()
		addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
		assocID, err := mux.Register(context.Background(), addr)
		if err != nil {
			_ = sess.WriteUDPAssocReply(rw, false, 0)
			slog.Debug("udp assoc failed", "target", addr, "err", err)
			return
		}
		if err := sess.WriteUDPAssocReply(rw, true, assocID); err != nil {
			return
		}
		slog.Debug("udp assoc registered", "target", addr, "assoc_id", assocID)

	}
}
