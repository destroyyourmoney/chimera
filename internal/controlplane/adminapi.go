package controlplane

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

func NewAdminMux(token string, accounts *AccountStore, catalog *CatalogStore, revocations *RevocationStore) (*http.ServeMux, error) {
	if token == "" {
		return nil, errors.New("controlplane: admin token must not be empty")
	}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/admin/accounts", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ExpiresAt   string `json:"expires_at"`
			DeviceLimit int    `json:"device_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		limit := body.DeviceLimit
		if limit <= 0 {
			limit = 5
		}
		number, err := accounts.CreateAccount(expiresAt, limit)
		if err != nil {
			slog.Error("controlplane: create account failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to create account")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"account_number": number})
	})

	mux.HandleFunc("POST /v1/admin/accounts/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AccountNumber string `json:"account_number"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := accounts.RevokeAccount(body.AccountNumber); err != nil {
			if errors.Is(err, ErrAccountNotFound) {
				writeErr(w, http.StatusNotFound, "no such account")
				return
			}
			slog.Error("controlplane: revoke account failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to revoke account")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /v1/admin/accounts/devices/reset", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AccountNumber string `json:"account_number"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		shortIDs, err := accounts.RemoveAllDevices(body.AccountNumber)
		if err != nil {
			if errors.Is(err, ErrAccountNotFound) {
				writeErr(w, http.StatusNotFound, "no such account")
				return
			}
			slog.Error("controlplane: remove devices failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to remove devices")
			return
		}

		for _, sid := range shortIDs {
			if err := revocations.Revoke(sid); err != nil {
				slog.Error("controlplane: revoke removed device failed", "short_id", sid, "err", err)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"removed_count": len(shortIDs),
			"short_ids":     shortIDs,
		})
	})

	mux.HandleFunc("POST /v1/admin/accounts/status", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AccountNumber string `json:"account_number"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		st, err := accounts.Status(body.AccountNumber)
		if err != nil {
			if errors.Is(err, ErrAccountNotFound) {
				writeErr(w, http.StatusNotFound, "no such account")
				return
			}
			slog.Error("controlplane: account status failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to get account status")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       st.Status,
			"expires_at":   st.ExpiresAt.Unix(),
			"device_count": st.DeviceCount,
			"device_limit": st.DeviceLimit,
		})
	})

	mux.HandleFunc("GET /v1/admin/servers", func(w http.ResponseWriter, r *http.Request) {
		servers, err := catalog.List()
		if err != nil {
			slog.Error("controlplane: list servers failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to list servers")
			return
		}
		writeJSON(w, http.StatusOK, servers)
	})

	mux.HandleFunc("POST /v1/admin/servers", func(w http.ResponseWriter, r *http.Request) {
		var srv CatalogServer
		if err := json.NewDecoder(r.Body).Decode(&srv); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		srv.Healthy = true
		id, err := catalog.Add(srv)
		if err != nil {
			slog.Error("controlplane: add server failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to add server")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("POST /v1/admin/servers/{id}/listeners", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		var body struct {
			Transport string `json:"transport"`
			Port      int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := catalog.AddListener(id, body.Transport, body.Port); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("DELETE /v1/admin/servers/{id}/listeners/{transport}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		found, err := catalog.RemoveListener(id, r.PathValue("transport"))
		if err != nil {
			slog.Error("controlplane: remove listener failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to remove listener")
			return
		}
		if !found {
			writeErr(w, http.StatusNotFound, "no such listener")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("DELETE /v1/admin/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		found, err := catalog.Remove(id)
		if err != nil {
			slog.Error("controlplane: remove server failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to remove server")
			return
		}
		if !found {
			writeErr(w, http.StatusNotFound, "no such server")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /v1/admin/revocations", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ShortIDHex string `json:"short_id_hex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := revocations.Revoke(body.ShortIDHex); err != nil {
			slog.Error("controlplane: revoke short id failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "failed to revoke")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	return withAdminAuth(token, mux), nil
}

func withAdminAuth(token string, next http.Handler) *http.ServeMux {
	want := []byte(token)
	wrapped := http.NewServeMux()
	wrapped.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if len(got) <= len(prefix) || got[:len(prefix)] != prefix ||
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), want) != 1 {
			writeErr(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
	return wrapped
}
