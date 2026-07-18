package controlplane

import "testing"

func TestRevocationSinceCursor(t *testing.T) {
	db := newTestDB(t)
	store := NewRevocationStore(db)

	if err := store.Revoke("aaaaaaaa"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := store.Revoke("bbbbbbbb"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	entries, etag, err := store.Since(0)
	if err != nil {
		t.Fatalf("Since(0): %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	more, nextEtag, err := store.Since(etag)
	if err != nil {
		t.Fatalf("Since(etag): %v", err)
	}
	if len(more) != 0 {
		t.Fatalf("expected 0 new entries, got %d", len(more))
	}
	if nextEtag != etag {
		t.Fatalf("expected etag to stay stable with no new revocations")
	}

	if err := store.Revoke("cccccccc"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	more, _, err = store.Since(etag)
	if err != nil {
		t.Fatalf("Since(etag) after new revoke: %v", err)
	}
	if len(more) != 1 || more[0].ShortIDHex != "cccccccc" {
		t.Fatalf("expected exactly the new revocation, got %+v", more)
	}
}

func TestRevocationIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	store := NewRevocationStore(db)
	if err := store.Revoke("aaaaaaaa"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := store.Revoke("aaaaaaaa"); err != nil {
		t.Fatalf("Revoke (again): %v", err)
	}
	entries, _, err := store.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected revoking the same sid twice to not duplicate, got %d entries", len(entries))
	}
}
