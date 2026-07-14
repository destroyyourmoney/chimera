// Package useracl is a dynamic, file-persisted allow-list of short IDs
// ("users") that can be added or revoked at runtime without restarting the
// CHIMERA server. It implements carrier.Allowlist, so it drops straight into
// server.Config.Allowlist / carrier.QUICServerConfig.Allowlist.
//
// A single YAML file is the source of truth. The process that runs the admin
// API mutates it directly and refreshes its own in-memory snapshot immediately;
// every process (including the TCP and QUIC carriers, which normally run as
// separate binaries/containers so they can't share Go-level state) polls the
// same file on a short interval and picks up changes — the same pattern
// internal/config.Watch already uses for hot-reloading the TLS fingerprint.
package useracl

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"chimera/internal/auth"
)

// PollInterval is how often a Store not actively mutating the file (e.g. the
// QUIC sibling process when the admin API runs in the TCP process) re-reads it
// to pick up changes made elsewhere.
const PollInterval = 5 * time.Second

// User is one allowed short ID and an operator-facing label ("Alice's phone").
type User struct {
	SID   string `yaml:"sid"`
	Label string `yaml:"label"`
}

// fileFormat is the on-disk YAML shape.
type fileFormat struct {
	Users []User `yaml:"users"`
}

// Store is a concurrent-safe, dynamic short-ID allow-list backed by a YAML
// file. The zero value is not usable; construct with Load.
type Store struct {
	path string
	snap atomic.Pointer[snapshot]
}

// snapshot is the immutable state swapped in on every reload/mutation.
type snapshot struct {
	users []User
	bySID map[string][]byte // hex sid -> decoded bytes, for Allowed()
}

// Load reads path if it exists (empty/absent = no users yet, matching the
// legacy "accept any" PoC convenience only if the caller falls back to it —
// Store itself, unlike StaticAllowlist, treats an empty set as reject-all,
// since a dynamic ACL with zero provisioned users should not silently open the
// server to anyone). The file is created on first Add if it doesn't exist yet.
func Load(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Watch polls the file every PollInterval until ctx is done, refreshing the
// in-memory snapshot whenever the on-disk content changes. Intended for the
// sibling process that doesn't own the admin API (e.g. the QUIC carrier when
// -admin-listen is only wired into the TCP carrier process).
func (s *Store) Watch(done <-chan struct{}) {
	t := time.NewTicker(PollInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if err := s.reload(); err != nil {
				slog.Debug("useracl: reload failed", "path", s.path, "err", err)
			}
		}
	}
}

func (s *Store) reload() error {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		s.snap.Store(&snapshot{bySID: map[string][]byte{}})
		return nil
	}
	if err != nil {
		return fmt.Errorf("useracl: open %q: %w", s.path, err)
	}
	defer f.Close()

	var ff fileFormat
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&ff); err != nil {
		return fmt.Errorf("useracl: parse %q: %w", s.path, err)
	}
	next := &snapshot{users: ff.Users, bySID: make(map[string][]byte, len(ff.Users))}
	for _, u := range ff.Users {
		raw, err := hex.DecodeString(u.SID)
		if err != nil {
			continue // skip malformed entries rather than failing the whole reload
		}
		next.bySID[u.SID] = raw
	}
	s.snap.Store(next)
	return nil
}

func (s *Store) current() *snapshot {
	sn := s.snap.Load()
	if sn == nil {
		return &snapshot{bySID: map[string][]byte{}}
	}
	return sn
}

// Allowed reports whether sid matches one of the currently provisioned users.
// Constant-time per candidate to avoid a membership timing oracle.
func (s *Store) Allowed(sid []byte) bool {
	for _, raw := range s.current().bySID {
		if subtle.ConstantTimeCompare(raw, sid) == 1 {
			return true
		}
	}
	return false
}

// List returns the currently provisioned users, most-recently-added last.
func (s *Store) List() []User {
	cur := s.current().users
	out := make([]User, len(cur))
	copy(out, cur)
	return out
}

// Add provisions a new random short ID under label and persists it. Returns
// the new user (with its generated SID).
func (s *Store) Add(label string) (User, error) {
	sidBytes := make([]byte, auth.ShortIDLen)
	if _, err := rand.Read(sidBytes); err != nil {
		return User{}, fmt.Errorf("useracl: generate sid: %w", err)
	}
	u := User{SID: hex.EncodeToString(sidBytes), Label: label}

	cur := s.current().users
	next := append(append([]User{}, cur...), u)
	if err := s.persist(next); err != nil {
		return User{}, err
	}
	return u, nil
}

// SeedIfEmpty persists users verbatim (exact SIDs, not freshly generated
// ones) but only if the store currently has zero users. This lets an operator
// turn on -users-file for a server that was already running with a static
// -sid/short_ids list without instantly locking out existing clients — the
// old sids become the first "users" instead of being silently replaced by new
// random ones.
func (s *Store) SeedIfEmpty(users []User) error {
	if len(s.current().users) > 0 || len(users) == 0 {
		return nil
	}
	return s.persist(users)
}

// Remove revokes the user with the given hex short ID. Reports whether a user
// was actually found and removed.
func (s *Store) Remove(sidHex string) (bool, error) {
	cur := s.current().users
	next := make([]User, 0, len(cur))
	found := false
	for _, u := range cur {
		if u.SID == sidHex {
			found = true
			continue
		}
		next = append(next, u)
	}
	if !found {
		return false, nil
	}
	if err := s.persist(next); err != nil {
		return false, err
	}
	return true, nil
}

// persist writes users to disk atomically (temp file + rename, so a reader
// polling concurrently — including our own Watch loop — never observes a
// half-written file) and refreshes the in-memory snapshot immediately.
func (s *Store) persist(users []User) error {
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("useracl: create temp file: %w", err)
	}
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(fileFormat{Users: users}); err != nil {
		f.Close()
		return fmt.Errorf("useracl: encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		f.Close()
		return fmt.Errorf("useracl: encode: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("useracl: close temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("useracl: rename into place: %w", err)
	}

	next := &snapshot{users: users, bySID: make(map[string][]byte, len(users))}
	for _, u := range users {
		if raw, err := hex.DecodeString(u.SID); err == nil {
			next.bySID[u.SID] = raw
		}
	}
	s.snap.Store(next)
	return nil
}
