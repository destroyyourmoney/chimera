package controlplane

import (
	"database/sql"
	"fmt"
)

type RevocationStore struct {
	db *sql.DB
}

func NewRevocationStore(db *sql.DB) *RevocationStore { return &RevocationStore{db: db} }

func (s *RevocationStore) Revoke(shortIDHex string) error {
	_, err := s.db.Exec(
		`INSERT INTO revocations (short_id_hex, revoked_at) VALUES (?, unixepoch())
		 ON CONFLICT(short_id_hex) DO NOTHING`,
		shortIDHex,
	)
	if err != nil {
		return fmt.Errorf("controlplane: revoke short id: %w", err)
	}
	return nil
}

type RevocationEntry struct {
	ShortIDHex string `json:"short_id_hex"`
	RevokedAt  int64  `json:"revoked_at"`
}

func (s *RevocationStore) Since(etag int64) (entries []RevocationEntry, nextEtag int64, err error) {
	rows, err := s.db.Query(
		`SELECT id, short_id_hex, revoked_at FROM revocations WHERE id > ? ORDER BY id ASC`,
		etag,
	)
	if err != nil {
		return nil, etag, fmt.Errorf("controlplane: list revocations: %w", err)
	}
	defer rows.Close()

	next := etag
	for rows.Next() {
		var id int64
		var e RevocationEntry
		if err := rows.Scan(&id, &e.ShortIDHex, &e.RevokedAt); err != nil {
			return nil, etag, fmt.Errorf("controlplane: scan revocation: %w", err)
		}
		entries = append(entries, e)
		if id > next {
			next = id
		}
	}
	return entries, next, rows.Err()
}
