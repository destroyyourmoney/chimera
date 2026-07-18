package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"chimera/internal/useracl"
)

type fakeStore struct {
	users []useracl.User
}

func (f *fakeStore) List() []useracl.User { return f.users }

func (f *fakeStore) Add(label string) (useracl.User, error) {
	u := useracl.User{SID: "aabbccdd", Label: label}
	f.users = append(f.users, u)
	return u, nil
}

func (f *fakeStore) Remove(sid string) (bool, error) {
	for i, u := range f.users {
		if u.SID == sid {
			f.users = append(f.users[:i], f.users[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func TestAuthRequired(t *testing.T) {
	srv := httptest.NewServer(withAuth("secret-token", newMux(&fakeStore{})))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/users")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", srv.URL+"/v1/users", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with wrong token: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", resp2.StatusCode)
	}
}

func TestAddListRemoveOverHTTP(t *testing.T) {
	store := &fakeStore{}
	srv := httptest.NewServer(withAuth("secret-token", newMux(store)))
	defer srv.Close()
	client := srv.Client()

	doAuthed := func(method, path, body string) *http.Response {
		var req *http.Request
		var err error
		if body != "" {
			req, err = http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		} else {
			req, err = http.NewRequest(method, srv.URL+path, nil)
		}
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer secret-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	addResp := doAuthed("POST", "/v1/users", `{"label":"Alice"}`)
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/users: status = %d, want 201", addResp.StatusCode)
	}
	var added useracl.User
	if err := json.NewDecoder(addResp.Body).Decode(&added); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	if added.Label != "Alice" || added.SID == "" {
		t.Fatalf("added user = %+v, want Label=Alice and non-empty SID", added)
	}

	listResp := doAuthed("GET", "/v1/users", "")
	defer listResp.Body.Close()
	var list []useracl.User
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(list) != 1 || list[0].SID != added.SID {
		t.Fatalf("list = %+v, want one entry matching %+v", list, added)
	}

	delResp := doAuthed("DELETE", "/v1/users/"+added.SID, "")
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want 204", delResp.StatusCode)
	}

	delAgainResp := doAuthed("DELETE", "/v1/users/"+added.SID, "")
	defer delAgainResp.Body.Close()
	if delAgainResp.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE (already gone): status = %d, want 404", delAgainResp.StatusCode)
	}
}

func TestServeRequiresToken(t *testing.T) {
	err := Serve(context.Background(), "127.0.0.1:0", "", &fakeStore{})
	if err == nil {
		t.Fatal("Serve with an empty token must return an error, not silently start unauthenticated")
	}
}
