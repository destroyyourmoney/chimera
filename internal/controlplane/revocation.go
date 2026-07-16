// Instant-revocation denylist (ROADMAP2 §1.4). Token TTL expiry is the
// primary revocation mechanism -- this list only exists to cut off a short
// ID before its token would naturally expire (e.g. a stolen/abused key).
// Data-plane servers poll GET /v1/revocations?since=<etag> on the same
// 5-second cadence useracl.Store.Watch already uses for its own file, and
// this endpoint is intentionally public/unauthenticated + cacheable: the
// content (which short IDs are revoked) isn't sensitive the way the
// catalog is, and gating it behind a token would only slow down the exact
// thing it exists to make fast.
package controlplane

import (
	"database/sql"
	"fmt"
)

type RevocationStore struct {
	db *sql.DB
}

func NewRevocationStore(db *sql.DB) *RevocationStore { return &RevocationStore{db: db} }

// Revoke adds shortIDHex to the denylist immediately. Idempotent -- revoking
// an already-revoked ID is not an error.
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

// RevocationEntry is one row of the public feed servers poll.
type RevocationEntry struct {
	ShortIDHex string `json:"short_id_hex"`
	RevokedAt  int64  `json:"revoked_at"`
}

// Since returns every revocation with rowid greater than the given etag,
// plus the new etag to pass next poll -- a cheap append-only cursor a
// server can resume from instead of re-fetching the whole list every 5s
// once the denylist grows large.
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
