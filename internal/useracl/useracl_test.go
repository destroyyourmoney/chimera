package useracl

import (
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestAddAllowRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.yaml")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// No users provisioned yet: everything is rejected (unlike StaticAllowlist,
	// an empty dynamic store must not default to accept-any).
	if s.Allowed(make([]byte, 4)) {
		t.Fatal("empty store must reject, not accept-any")
	}

	u, err := s.Add("Alice")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	sidBytes, err := hex.DecodeString(u.SID)
	if err != nil {
		t.Fatalf("decode generated sid: %v", err)
	}
	if len(sidBytes) != 4 {
		t.Fatalf("sid length = %d, want 4", len(sidBytes))
	}
	if !s.Allowed(sidBytes) {
		t.Fatal("newly added sid must be allowed")
	}

	list := s.List()
	if len(list) != 1 || list[0].Label != "Alice" {
		t.Fatalf("List = %+v, want one Alice entry", list)
	}

	ok, err := s.Remove(u.SID)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !ok {
		t.Fatal("Remove should report found=true for an existing sid")
	}
	if s.Allowed(sidBytes) {
		t.Fatal("revoked sid must no longer be allowed")
	}

	ok, err = s.Remove(u.SID)
	if err != nil {
		t.Fatalf("Remove (already gone): %v", err)
	}
	if ok {
		t.Fatal("removing an already-removed sid should report found=false")
	}
}

func TestPersistenceAcrossLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.yaml")
	s1, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	u, err := s1.Add("Bob")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	s2, err := Load(path)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	sidBytes, _ := hex.DecodeString(u.SID)
	if !s2.Allowed(sidBytes) {
		t.Fatal("a fresh Store from the same path must see users persisted by another Store")
	}
}

func TestReloadPicksUpExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.yaml")
	writer, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	reader, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	u, err := writer.Add("Carol")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	sidBytes, _ := hex.DecodeString(u.SID)

	if reader.Allowed(sidBytes) {
		t.Fatal("reader should not see the change before an explicit reload")
	}
	if err := reader.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reader.Allowed(sidBytes) {
		t.Fatal("reader should see the change after reload() — simulates the sibling QUIC process's poll loop")
	}
}

func TestLoadMissingFileIsEmptyNotError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load of a missing file should not error: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("missing file should mean zero users, not an error")
	}
}
