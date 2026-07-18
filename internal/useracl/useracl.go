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

const PollInterval = 5 * time.Second

type User struct {
	SID   string `yaml:"sid"`
	Label string `yaml:"label"`
}

type fileFormat struct {
	Users []User `yaml:"users"`
}

type Store struct {
	path string
	snap atomic.Pointer[snapshot]
}

type snapshot struct {
	users []User
	bySID map[string][]byte
}

func Load(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

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
			continue
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

func (s *Store) Allowed(sid []byte) bool {
	for _, raw := range s.current().bySID {
		if subtle.ConstantTimeCompare(raw, sid) == 1 {
			return true
		}
	}
	return false
}

func (s *Store) List() []User {
	cur := s.current().users
	out := make([]User, len(cur))
	copy(out, cur)
	return out
}

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

func (s *Store) SeedIfEmpty(users []User) error {
	if len(s.current().users) > 0 || len(users) == 0 {
		return nil
	}
	return s.persist(users)
}

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
