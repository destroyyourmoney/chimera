// Package controlplane implements the "ключ → доступ" account service
// (ROADMAP2 §0/§1/§2): account redemption, Ed25519 capability tokens, the
// curated server catalog, and instant-revocation. It is the only component
// that touches the database — everything else (data-plane servers, the
// client) only ever calls through its HTTP APIs or verifies its signed
// tokens locally.
package controlplane

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo toolchain required
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// OpenDB opens (creating if needed) the SQLite database at path and applies
// any migrations from migrations/*.sql not yet recorded in
// schema_migrations. Filenames sort lexically (0001_, 0002_, ...), so a
// Postgres move later is "point this at a different DSN + driver", not a
// schema rewrite -- the SQL itself avoids SQLite-specific types on purpose
// (ROADMAP2 §1).
func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("controlplane: open db: %w", err)
	}
	// SQLite only tolerates one writer at a time; the control-plane's write
	// rate (redeem/refresh/catalog-admin) is low enough that serializing
	// through a single connection is simpler and safer than fighting
	// SQLITE_BUSY under concurrent writers.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("controlplane: create schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("controlplane: read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("controlplane: read embedded migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		if applied[name] {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("controlplane: read migration %s: %w", name, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("controlplane: apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, unixepoch())`, name); err != nil {
			tx.Rollback()
			return fmt.Errorf("controlplane: record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
