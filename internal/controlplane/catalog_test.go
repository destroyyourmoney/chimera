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

func TestCatalogAddDefaultsToOneRealityListener(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)

	id, err := store.Add(CatalogServer{
		Host: "vps.example.com", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 server, got %d", len(list))
	}
	if len(list[0].Listeners) != 1 {
		t.Fatalf("expected exactly 1 implicit listener, got %+v", list[0].Listeners)
	}
	if got := list[0].Listeners[0]; got.Transport != "reality" || got.Port != 443 {
		t.Fatalf("expected {reality 443}, got %+v", got)
	}
	_ = id
}

func TestCatalogAddWithExplicitListeners(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)

	_, err := store.Add(CatalogServer{
		Host: "vps.example.com", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y",
		Listeners: []CatalogListener{
			{Transport: "reality", Port: 443},
			{Transport: "quic", Port: 8443},
			{Transport: "ss", Port: 8444},
			{Transport: "dot", Port: 8445},
		},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list[0].Listeners) != 4 {
		t.Fatalf("expected 4 listeners, got %+v", list[0].Listeners)
	}
}

func TestCatalogAddListener(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)

	id, err := store.Add(CatalogServer{
		Host: "vps.example.com", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := store.AddListener(id, "quic", 8443); err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	if err := store.AddListener(id, "ss", 8444); err != nil {
		t.Fatalf("AddListener: %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list[0].Listeners) != 3 {
		t.Fatalf("expected 3 listeners (reality + quic + ss), got %+v", list[0].Listeners)
	}

	if err := store.AddListener(id, "quic", 9443); err != nil {
		t.Fatalf("AddListener (update): %v", err)
	}
	list, err = store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list[0].Listeners) != 3 {
		t.Fatalf("expected AddListener to update, not duplicate: got %+v", list[0].Listeners)
	}
	var quicPort int
	for _, l := range list[0].Listeners {
		if l.Transport == "quic" {
			quicPort = l.Port
		}
	}
	if quicPort != 9443 {
		t.Fatalf("expected quic listener updated to port 9443, got %d", quicPort)
	}
}

func TestCatalogAddListenerRejectsInvalidInput(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)
	id, err := store.Add(CatalogServer{Host: "h", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.AddListener(id, "", 8443); err == nil {
		t.Fatal("expected an error for an empty transport")
	}
	if err := store.AddListener(id, "quic", 0); err == nil {
		t.Fatal("expected an error for an invalid port")
	}
	if err := store.AddListener(id, "quic", 70000); err == nil {
		t.Fatal("expected an error for an out-of-range port")
	}
}

func TestCatalogRemoveListener(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)
	id, err := store.Add(CatalogServer{
		Host: "h", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y",
		Listeners: []CatalogListener{{Transport: "reality", Port: 443}, {Transport: "quic", Port: 8443}},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	found, err := store.RemoveListener(id, "quic")
	if err != nil {
		t.Fatalf("RemoveListener: %v", err)
	}
	if !found {
		t.Fatal("expected RemoveListener to report found")
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list[0].Listeners) != 1 || list[0].Listeners[0].Transport != "reality" {
		t.Fatalf("expected only reality left, got %+v", list[0].Listeners)
	}

	found, err = store.RemoveListener(id, "quic")
	if err != nil {
		t.Fatalf("RemoveListener (already gone): %v", err)
	}
	if found {
		t.Fatal("expected RemoveListener of an already-removed transport to report not found")
	}
}

func TestCatalogRemoveServerCascadesListeners(t *testing.T) {
	db := newTestDB(t)
	store := NewCatalogStore(db)
	id, err := store.Add(CatalogServer{
		Host: "h", Port: 443, PubKey: "pk", SNI: "sni", Country: "X", City: "Y",
		Listeners: []CatalogListener{{Transport: "reality", Port: 443}, {Transport: "quic", Port: 8443}},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := store.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM listeners WHERE server_id = ?`, id).Scan(&count); err != nil {
		t.Fatalf("count listeners: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected ON DELETE CASCADE to remove orphaned listeners, found %d left", count)
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
