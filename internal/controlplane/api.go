package controlplane

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"chimera/internal/ratelimit"
)

type API struct {
	accounts    *AccountStore
	catalog     *CatalogStore
	revocations *RevocationStore
	signer      *Signer
	verifier    *Verifier

	ipLimiter    *ratelimit.Limiter
	tokenLimiter *ratelimit.Limiter

	mirrors []string
}

func NewAPI(accounts *AccountStore, catalog *CatalogStore, revocations *RevocationStore, signer *Signer, verifier *Verifier, mirrors []string) *API {
	return &API{
		accounts:    accounts,
		catalog:     catalog,
		revocations: revocations,
		signer:      signer,
		verifier:    verifier,
		mirrors:     mirrors,

		ipLimiter:    ratelimit.New(1, 5),
		tokenLimiter: ratelimit.New(1, 5),
	}
}

func (a *API) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/session/redeem", a.handleRedeem)
	mux.HandleFunc("POST /v1/session/refresh", a.handleRefresh)
	mux.HandleFunc("GET /v1/catalog", a.handleCatalog)
	mux.HandleFunc("GET /v1/account", a.handleAccountInfo)
	mux.HandleFunc("GET /v1/revocations", a.handleRevocations)
	mux.HandleFunc("GET /v1/mirrors", a.handleMirrors)
	return mux
}

func (a *API) handleMirrors(w http.ResponseWriter, r *http.Request) {
	if !a.ipLimiter.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	body, err := json.Marshal(a.mirrors)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mirrors":   a.mirrors,
		"signature": a.signer.SignBytes(body),
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *API) handleRedeem(w http.ResponseWriter, r *http.Request) {
	if !a.ipLimiter.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var body struct {
		AccountNumber string `json:"account_number"`
		DevicePubKey  string `json:"device_pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.AccountNumber == "" || body.DevicePubKey == "" {
		writeErr(w, http.StatusBadRequest, "account_number and device_pubkey are required")
		return
	}

	result, err := a.accounts.Redeem(body.AccountNumber, body.DevicePubKey)
	if err != nil {
		writeErr(w, statusForAccountErr(err), publicMessageFor(err))
		return
	}

	token, err := a.signer.Sign(TokenPayload{
		ShortIDHex:    result.ShortIDHex,
		AccountIDHash: result.AccountIDHash,
		DevicePubKey:  body.DevicePubKey,
	})
	if err != nil {
		slog.Error("controlplane: sign token failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"token": token, "short_id_hex": result.ShortIDHex})
}

func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !a.ipLimiter.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	payload, err := a.verifier.Verify(body.Token)
	if err != nil && !errors.Is(err, ErrTokenExpired) {

		writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}

	result, err := a.accounts.Refresh(payload.ShortIDHex)
	if err != nil {
		writeErr(w, statusForAccountErr(err), publicMessageFor(err))
		return
	}
	token, err := a.signer.Sign(TokenPayload{
		ShortIDHex:    result.ShortIDHex,
		AccountIDHash: result.AccountIDHash,
		DevicePubKey:  payload.DevicePubKey,
	})
	if err != nil {
		slog.Error("controlplane: sign token failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "short_id_hex": result.ShortIDHex})
}

func (a *API) handleCatalog(w http.ResponseWriter, r *http.Request) {
	if !a.ipLimiter.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	token := bearerToken(r)
	if token == "" {
		writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	payload, err := a.verifier.Verify(token)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	if !a.tokenLimiter.Allow(payload.ShortIDHex) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	servers, err := a.catalog.List()
	if err != nil {
		slog.Error("controlplane: list catalog failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, servers)
}

func (a *API) handleAccountInfo(w http.ResponseWriter, r *http.Request) {
	if !a.ipLimiter.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	token := bearerToken(r)
	if token == "" {
		writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	payload, err := a.verifier.Verify(token)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	if !a.tokenLimiter.Allow(payload.ShortIDHex) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	info, err := a.accounts.Info(payload.ShortIDHex)
	if err != nil {
		writeErr(w, statusForAccountErr(err), publicMessageFor(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       info.Status,
		"expires_at":   info.ExpiresAt.Unix(),
		"device_count": info.DeviceCount,
		"device_limit": info.DeviceLimit,
	})
}

func (a *API) handleRevocations(w http.ResponseWriter, r *http.Request) {
	if !a.ipLimiter.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	since := int64(0)
	if s := r.URL.Query().Get("since"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid since")
			return
		}
		since = v
	}
	entries, nextEtag, err := a.revocations.Since(since)
	if err != nil {
		slog.Error("controlplane: list revocations failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revocations": entries,
		"etag":        nextEtag,
	})
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if len(got) <= len(prefix) || !strings.HasPrefix(got, prefix) {
		return ""
	}
	return got[len(prefix):]
}

func statusForAccountErr(err error) int {
	switch {
	case errors.Is(err, ErrAccountNotFound):
		return http.StatusUnauthorized
	case errors.Is(err, ErrAccountInactive), errors.Is(err, ErrAccountExpired):
		return http.StatusForbidden
	case errors.Is(err, ErrDeviceLimit):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func publicMessageFor(err error) string {
	switch {
	case errors.Is(err, ErrAccountNotFound):
		return "invalid account number"
	case errors.Is(err, ErrAccountInactive):
		return "account is not active"
	case errors.Is(err, ErrAccountExpired):
		return "account has expired"
	case errors.Is(err, ErrDeviceLimit):
		return "device limit reached for this account"
	default:
		return "internal error"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
