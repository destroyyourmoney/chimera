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

	// Listeners is every transport this server actually has a running
	// `chimera server -transport X` process for (ROADMAP2 §3/§4: Reality,
	// QUIC/H3, Shadowsocks-AEAD, DNS-over-TCP can each run as a separate
	// listener on the same box). `Host`/`Port` above stay the default/
	// primary (Reality) endpoint for any client too old to read this field --
	// added, never breaking, per catalog.go's existing "no false promises"
	// stance: a transport with no listener here must not be offered to the
	// user as if it were dialable against this server (see
	// app/lib/anticensorship_page.dart).
	Listeners []CatalogListener `json:"listeners"`
}

// CatalogListener is one transport endpoint on a CatalogServer -- see the
// `listeners` table (migrations/0002_listeners.sql). Transport is one of
// "reality", "quic", "ss", "dot", matching internal/subscription.Parse's
// `mode=` query-param vocabulary (empty/"reality" both mean Reality/TCP on
// the wire; stored as "reality" here so the catalog is never ambiguous
// about whether a listener was omitted vs. deliberately Reality).
type CatalogListener struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
}

type CatalogStore struct {
	db *sql.DB
}

func NewCatalogStore(db *sql.DB) *CatalogStore { return &CatalogStore{db: db} }

// Add registers a server the operator has already deployed via
// internal/provision.SSHDeployer.Deploy (ROADMAP2 §2's two-step process --
// this is step 2). If srv.Listeners is empty, it defaults to the single
// implied Reality/TCP listener at srv.Port -- the same shape every caller
// used before multi-transport listeners existed (chimera-control-cli's
// `catalog add` still only takes -host/-port, no transport flag), so this
// never changes behavior for an operator who hasn't adopted the new
// per-transport deploy flow yet.
func (s *CatalogStore) Add(srv CatalogServer) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("controlplane: add server: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO servers (host, port, pubkey, sni, fingerprint, country, city, load_pct, healthy, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())`,
		srv.Host, srv.Port, srv.PubKey, srv.SNI, srv.Fingerprint, srv.Country, srv.City, srv.LoadPct, boolToInt(srv.Healthy),
	)
	if err != nil {
		return 0, fmt.Errorf("controlplane: add server: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("controlplane: add server: %w", err)
	}

	listeners := srv.Listeners
	if len(listeners) == 0 {
		listeners = []CatalogListener{{Transport: "reality", Port: srv.Port}}
	}
	for _, l := range listeners {
		if _, err := tx.Exec(
			`INSERT INTO listeners (server_id, transport, port, created_at) VALUES (?, ?, ?, unixepoch())`,
			id, l.Transport, l.Port,
		); err != nil {
			return 0, fmt.Errorf("controlplane: add listener %q: %w", l.Transport, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("controlplane: add server: %w", err)
	}
	return id, nil
}

// AddListener registers (or, on a redeploy to a new port, updates) one
// transport listener for an already-catalogued server -- the incremental
// counterpart to Add's bulk `Listeners` for wiring up a QUIC/Shadowsocks-
// AEAD/DNS-over-TCP process deployed after the server's initial (Reality)
// registration. See internal/provision.DeployResult.Listeners, which is
// what an operator's script loops over to call this once per transport.
func (s *CatalogStore) AddListener(serverID int64, transport string, port int) error {
	if transport == "" {
		return fmt.Errorf("controlplane: add listener: transport must not be empty")
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("controlplane: add listener: invalid port %d", port)
	}
	_, err := s.db.Exec(
		`INSERT INTO listeners (server_id, transport, port, created_at) VALUES (?, ?, ?, unixepoch())
		 ON CONFLICT (server_id, transport) DO UPDATE SET port = excluded.port`,
		serverID, transport, port,
	)
	if err != nil {
		return fmt.Errorf("controlplane: add listener: %w", err)
	}
	return nil
}

// RemoveListener decommissions one transport listener without removing the
// whole server (e.g. its QUIC process was retired but Reality stays up) --
// reports whether a row was actually found.
func (s *CatalogStore) RemoveListener(serverID int64, transport string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM listeners WHERE server_id = ? AND transport = ?`, serverID, transport)
	if err != nil {
		return false, fmt.Errorf("controlplane: remove listener: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
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
// GET /v1/catalog serializes directly. Every returned CatalogServer has its
// Listeners populated (never nil -- see the same null-vs-empty-array
// reasoning as the out slice below).
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
		srv.Listeners = make([]CatalogListener, 0)
		out = append(out, srv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Merge in listeners by server_id. Built after `out` is fully populated
	// above (and never appended to again below), so these pointers into it
	// stay valid -- no further slice growth to invalidate them.
	byID := make(map[int64]*CatalogServer, len(out))
	for i := range out {
		byID[out[i].ID] = &out[i]
	}

	lrows, err := s.db.Query(`SELECT server_id, transport, port FROM listeners ORDER BY server_id, transport`)
	if err != nil {
		return nil, fmt.Errorf("controlplane: list listeners: %w", err)
	}
	defer lrows.Close()
	for lrows.Next() {
		var serverID int64
		var l CatalogListener
		if err := lrows.Scan(&serverID, &l.Transport, &l.Port); err != nil {
			return nil, fmt.Errorf("controlplane: scan listener: %w", err)
		}
		if srv, ok := byID[serverID]; ok {
			srv.Listeners = append(srv.Listeners, l)
		}
	}
	return out, lrows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
