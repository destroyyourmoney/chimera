package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const testAdminToken = "test-admin-token"

func newTestAdminMux(t *testing.T) (*http.ServeMux, *CatalogStore) {
	t.Helper()
	db := newTestDB(t)
	catalog := NewCatalogStore(db)
	mux, err := NewAdminMux(testAdminToken, NewAccountStore(db), catalog, NewRevocationStore(db))
	if err != nil {
		t.Fatalf("NewAdminMux: %v", err)
	}
	return mux, catalog
}

func adminDo(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestAdminResetDevicesRoute(t *testing.T) {
	db := newTestDB(t)
	catalog := NewCatalogStore(db)
	accounts := NewAccountStore(db)
	revocations := NewRevocationStore(db)
	mux, err := NewAdminMux(testAdminToken, accounts, catalog, revocations)
	if err != nil {
		t.Fatalf("NewAdminMux: %v", err)
	}

	number, err := accounts.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	res1, err := accounts.Redeem(number, "device-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if _, err := accounts.Redeem(number, "device-2"); err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	rec := adminDo(t, mux, "POST", "/v1/admin/accounts/devices/reset", map[string]any{
		"account_number": number,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		RemovedCount int      `json:"removed_count"`
		ShortIDs     []string `json:"short_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.RemovedCount != 2 {
		t.Fatalf("expected removed_count=2, got %+v", resp)
	}

	entries, _, err := revocations.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	revoked := map[string]bool{}
	for _, e := range entries {
		revoked[e.ShortIDHex] = true
	}
	if !revoked[res1.ShortIDHex] {
		t.Fatalf("expected %q to be on the revocation list, got %+v", res1.ShortIDHex, entries)
	}

	count, _, err := accounts.DeviceCount(number)
	if err != nil {
		t.Fatalf("DeviceCount: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 devices left, got %d", count)
	}
}

func TestAdminResetDevicesRouteUnknownAccount(t *testing.T) {
	mux, _ := newTestAdminMux(t)
	rec := adminDo(t, mux, "POST", "/v1/admin/accounts/devices/reset", map[string]any{
		"account_number": "0000-0000-0000-0000",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminAddListenerRoute(t *testing.T) {
	mux, catalog := newTestAdminMux(t)
	id, err := catalog.Add(CatalogServer{Host: "h", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	rec := adminDo(t, mux, "POST", "/v1/admin/servers/"+itoa(id)+"/listeners", map[string]any{
		"transport": "quic", "port": 8443,
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	list, err := catalog.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list[0].Listeners) != 2 {
		t.Fatalf("expected 2 listeners after admin add, got %+v", list[0].Listeners)
	}
}

func TestAdminAddListenerRouteRejectsBadInput(t *testing.T) {
	mux, catalog := newTestAdminMux(t)
	id, err := catalog.Add(CatalogServer{Host: "h", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	rec := adminDo(t, mux, "POST", "/v1/admin/servers/"+itoa(id)+"/listeners", map[string]any{
		"transport": "", "port": 8443,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty transport, got %d", rec.Code)
	}
}

func TestAdminRemoveListenerRoute(t *testing.T) {
	mux, catalog := newTestAdminMux(t)
	id, err := catalog.Add(CatalogServer{
		Host: "h", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y",
		Listeners: []CatalogListener{{Transport: "reality", Port: 443}, {Transport: "quic", Port: 8443}},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	rec := adminDo(t, mux, "DELETE", "/v1/admin/servers/"+itoa(id)+"/listeners/quic", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = adminDo(t, mux, "DELETE", "/v1/admin/servers/"+itoa(id)+"/listeners/quic", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 removing an already-removed listener, got %d", rec.Code)
	}
}

func TestAdminServersRouteRejectsMissingBearer(t *testing.T) {
	mux, _ := newTestAdminMux(t)
	req := httptest.NewRequest("GET", "/v1/admin/servers", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no bearer token, got %d", rec.Code)
	}
}

func TestAdminAddServerRouteAcceptsInlineListeners(t *testing.T) {
	mux, catalog := newTestAdminMux(t)
	rec := adminDo(t, mux, "POST", "/v1/admin/servers", map[string]any{
		"host": "h", "port": 443, "pubkey": "pk", "sni": "sni", "country": "X", "city": "Y",
		"listeners": []map[string]any{
			{"transport": "reality", "port": 443},
			{"transport": "ss", "port": 8444},
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	list, err := catalog.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list[0].Listeners) != 2 {
		t.Fatalf("expected 2 listeners from inline POST body, got %+v", list[0].Listeners)
	}
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}
