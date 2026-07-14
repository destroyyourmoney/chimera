// Package admin exposes a small token-authenticated HTTP API over an
// internal/useracl.Store so an operator (or, more commonly, the CHIMERA
// desktop app talking to a server it manages) can provision or revoke a
// chimera:// invite link for someone else without shelling into the box.
//
// It deliberately does not know anything about pbk/sni/fp/mode — those are
// static per-server and the caller (already holding them, e.g. from the
// original chimera:// link it used to add this server) fills them in when it
// builds the shareable link from the {sid,label} this API returns.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"chimera/internal/useracl"
)

// Store is the subset of *useracl.Store the admin API depends on, so tests can
// substitute a fake.
type Store interface {
	List() []useracl.User
	Add(label string) (useracl.User, error)
	Remove(sidHex string) (bool, error)
}

// Serve runs the admin HTTP API on addr until ctx is cancelled. Every request
// must carry "Authorization: Bearer <token>"; token should be a long random
// value generated once at server setup (see cmd/chimera's -admin-token flag).
//
// addr should normally be loopback-only (e.g. "127.0.0.1:8901") with access
// via an SSH tunnel, since this API can mint working VPN invites; it is
// token-gated regardless so a misconfigured bind isn't an open door.
func Serve(ctx context.Context, addr, token string, store Store) error {
	if token == "" {
		return errors.New("admin: token must not be empty")
	}
	srv := &http.Server{Addr: addr, Handler: withAuth(token, newMux(store))}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	slog.Info("admin api up", "listen", addr)
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func newMux(store Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/users", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.List())
	})
	mux.HandleFunc("POST /v1/users", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Label string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		u, err := store.Add(body.Label)
		if err != nil {
			slog.Warn("admin: add user failed", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to add user")
			return
		}
		writeJSON(w, http.StatusCreated, u)
	})
	mux.HandleFunc("DELETE /v1/users/{sid}", func(w http.ResponseWriter, r *http.Request) {
		sid := r.PathValue("sid")
		found, err := store.Remove(sid)
		if err != nil {
			slog.Warn("admin: remove user failed", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to remove user")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "no such user")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// withAuth requires a matching Bearer token on every request. Uses a
// constant-time comparison so response timing can't be used to brute-force
// the token byte-by-byte.
func withAuth(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if len(got) <= len(prefix) || got[:len(prefix)] != prefix ||
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), want) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// LoopbackOnly reports whether addr resolves to a loopback address, used to
// warn the operator loudly if -admin-listen is bound wider than that.
func LoopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false // "" / ":port" binds all interfaces
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
