// Curated server catalog (ROADMAP2 §2). Rows are inserted only via
// chimera-control-cli (adminapi.go), never over the public API -- ordinary
// clients only ever read the list through GET /v1/catalog, which requires
// a valid token (ROADMAP2 §0.1 п.1: the catalog is not a public,
// unauthenticated endpoint).
package controlplane

import (
	"database/sql"
	"fmt"
)

// CatalogServer is the shape both `GET /v1/catalog` (client-facing, no
// pubkey/fingerprint stripped -- the client needs them to dial) and the
// admin CLI operate on. Field names mirror carrier.Config 1:1 per
// ROADMAP2 §1/§2.
type CatalogServer struct {
	ID          int64  `json:"id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	PubKey      string `json:"pubkey"`
	SNI         string `json:"sni"`
	Fingerprint string `json:"fp"`
	Country     string `json:"country"`
	City        string `json:"city"`
	LoadPct     int    `json:"load_pct"`
	Healthy     bool   `json:"healthy"`
}

type CatalogStore struct {
	db *sql.DB
}

func NewCatalogStore(db *sql.DB) *CatalogStore { return &CatalogStore{db: db} }

// Add registers a server the operator has already deployed via
// internal/provision.SSHDeployer.Deploy (ROADMAP2 §2's two-step process --
// this is step 2).
func (s *CatalogStore) Add(srv CatalogServer) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO servers (host, port, pubkey, sni, fingerprint, country, city, load_pct, healthy, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())`,
		srv.Host, srv.Port, srv.PubKey, srv.SNI, srv.Fingerprint, srv.Country, srv.City, srv.LoadPct, boolToInt(srv.Healthy),
	)
	if err != nil {
		return 0, fmt.Errorf("controlplane: add server: %w", err)
	}
	return res.LastInsertId()
}

// Remove deletes a server from the catalog (host is decommissioned or
// being replaced) -- reports whether a row was actually found.
func (s *CatalogStore) Remove(id int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM servers WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("controlplane: remove server: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetHealth updates load/healthy -- called by whatever health-check loop
// the operator runs (out of scope for this plan; a stub for now, same
// spirit as ServerPing on the client side).
func (s *CatalogStore) SetHealth(id int64, loadPct int, healthy bool) error {
	_, err := s.db.Exec(`UPDATE servers SET load_pct = ?, healthy = ? WHERE id = ?`, loadPct, boolToInt(healthy), id)
	if err != nil {
		return fmt.Errorf("controlplane: set server health: %w", err)
	}
	return nil
}

// List returns the full catalog, healthy servers first -- this is what
// GET /v1/catalog serializes directly.
func (s *CatalogStore) List() ([]CatalogServer, error) {
	rows, err := s.db.Query(
		`SELECT id, host, port, pubkey, sni, fingerprint, country, city, load_pct, healthy
		 FROM servers ORDER BY healthy DESC, load_pct ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("controlplane: list servers: %w", err)
	}
	defer rows.Close()

	// Non-nil even with zero rows: encoding/json serializes a nil slice as
	// `null`, and GET /v1/catalog's caller (app/lib/catalog_page.dart) does
	// `jsonDecode(body) as List<dynamic>`, which throws a type-cast error on
	// `null` instead of parsing an empty list.
	out := make([]CatalogServer, 0)
	for rows.Next() {
		var srv CatalogServer
		var healthyInt int
		if err := rows.Scan(&srv.ID, &srv.Host, &srv.Port, &srv.PubKey, &srv.SNI, &srv.Fingerprint, &srv.Country, &srv.City, &srv.LoadPct, &healthyInt); err != nil {
			return nil, fmt.Errorf("controlplane: scan server: %w", err)
		}
		srv.Healthy = healthyInt != 0
		out = append(out, srv)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
