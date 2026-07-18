package controlplane

import (
	"database/sql"
	"fmt"
)

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

	Listeners []CatalogListener `json:"listeners"`
}

type CatalogListener struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
}

type CatalogStore struct {
	db *sql.DB
}

func NewCatalogStore(db *sql.DB) *CatalogStore { return &CatalogStore{db: db} }

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

func (s *CatalogStore) RemoveListener(serverID int64, transport string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM listeners WHERE server_id = ? AND transport = ?`, serverID, transport)
	if err != nil {
		return false, fmt.Errorf("controlplane: remove listener: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *CatalogStore) Remove(id int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM servers WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("controlplane: remove server: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *CatalogStore) SetHealth(id int64, loadPct int, healthy bool) error {
	_, err := s.db.Exec(`UPDATE servers SET load_pct = ?, healthy = ? WHERE id = ?`, loadPct, boolToInt(healthy), id)
	if err != nil {
		return fmt.Errorf("controlplane: set server health: %w", err)
	}
	return nil
}

func (s *CatalogStore) List() ([]CatalogServer, error) {
	rows, err := s.db.Query(
		`SELECT id, host, port, pubkey, sni, fingerprint, country, city, load_pct, healthy
		 FROM servers ORDER BY healthy DESC, load_pct ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("controlplane: list servers: %w", err)
	}
	defer rows.Close()

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
