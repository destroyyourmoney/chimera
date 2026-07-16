package controlplane

import "testing"

func TestCatalogAddListRemove(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)

	id1, err := store.Add(CatalogServer{
		Host: "vps1.example.com", Port: 443, PubKey: "pk1", SNI: "www.microsoft.com",
		Country: "Sweden", City: "Stockholm", Healthy: true,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	id2, err := store.Add(CatalogServer{
		Host: "vps2.example.com", Port: 443, PubKey: "pk2", SNI: "www.microsoft.com",
		Country: "Netherlands", City: "Amsterdam", Healthy: false, LoadPct: 50,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(list))
	}
	// Healthy servers sort first.
	if list[0].ID != id1 {
		t.Fatalf("expected healthy server (id=%d) first, got id=%d", id1, list[0].ID)
	}

	found, err := store.Remove(id2)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !found {
		t.Fatal("expected Remove to report the server was found")
	}
	list, err = store.List()
	if err != nil {
		t.Fatalf("List after remove: %v", err)
	}
	if len(list) != 1 || list[0].ID != id1 {
		t.Fatalf("expected only id=%d left, got %+v", id1, list)
	}

	found, err = store.Remove(id2)
	if err != nil {
		t.Fatalf("Remove (already gone): %v", err)
	}
	if found {
		t.Fatal("expected Remove of an already-removed id to report not found")
	}
}

func TestCatalogSetHealth(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)
	id, err := store.Add(CatalogServer{Host: "vps.example.com", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.SetHealth(id, 77, false); err != nil {
		t.Fatalf("SetHealth: %v", err)
	}
	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if list[0].LoadPct != 77 || list[0].Healthy {
		t.Fatalf("expected load=77 healthy=false, got %+v", list[0])
	}
}
