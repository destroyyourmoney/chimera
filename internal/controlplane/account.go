// Account issuance and redemption (ROADMAP2 §1). Billing/payment is
// explicitly out of scope (ROADMAP2 Context) -- accounts are created by
// `chimera-control-cli account create`, run by whoever/whatever handles
// payment out-of-band; this package only ever sees `sha256(number)`, never
// the number itself once issued.
package controlplane

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// keyAlphabet is Crockford base32 minus 0/O/1/I (ROADMAP2 §1), matching
// app/lib/account_store.dart's client-side normalizeAccountNumber exactly --
// the two must agree byte-for-byte or a key valid on one side would be
// rejected by the other.
const keyAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"

// GenerateAccountNumber returns a fresh 16-character key grouped
// `XXXX-XXXX-XXXX-XXXX`, drawn from a CSPRNG. At 30 symbols^16 the
// keyspace is >78 bits of entropy -- see ROADMAP2 §1 for the comparison
// against Mullvad's ~53-bit all-numeric scheme.
func GenerateAccountNumber() (string, error) {
	const n = 16
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("controlplane: generate account number: %w", err)
	}
	var b strings.Builder
	for i, v := range raw {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(keyAlphabet[int(v)%len(keyAlphabet)])
	}
	return b.String(), nil
}

func hashAccountNumber(number string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(number, "-", ""))
	return hashHex(normalized)
}

// hashHex is sha256(s) as hex -- used both for the account number itself
// and, one layer deeper, to derive AccountIDHash from number_hash so the
// token payload never carries anything the number could be recovered from.
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type AccountStatus string

const (
	StatusActive  AccountStatus = "active"
	StatusRevoked AccountStatus = "revoked"
)

type Account struct {
	ID          int64
	NumberHash  string
	Status      AccountStatus
	ExpiresAt   time.Time
	DeviceLimit int
}

var (
	ErrAccountNotFound   = errors.New("controlplane: account not found")
	ErrAccountInactive   = errors.New("controlplane: account not active")
	ErrAccountExpired    = errors.New("controlplane: account expired")
	ErrDeviceLimit       = errors.New("controlplane: device limit reached")
	ErrAccountsClosed    = errors.New("controlplane: account store closed")
)

// AccountStore is the sole owner of `accounts`/`devices` rows.
type AccountStore struct {
	db *sql.DB
}

func NewAccountStore(db *sql.DB) *AccountStore { return &AccountStore{db: db} }

// CreateAccount provisions a new account and returns the plaintext number --
// the only moment it ever exists outside the operator's own hands. Called
// only from chimera-control-cli, never over the network (ROADMAP2 §2).
func (s *AccountStore) CreateAccount(expiresAt time.Time, deviceLimit int) (number string, err error) {
	number, err = GenerateAccountNumber()
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(
		`INSERT INTO accounts (number_hash, status, expires_at, device_limit, created_at)
		 VALUES (?, ?, ?, ?, unixepoch())`,
		hashAccountNumber(number), StatusActive, expiresAt.Unix(), deviceLimit,
	)
	if err != nil {
		return "", fmt.Errorf("controlplane: create account: %w", err)
	}
	return number, nil
}

// RevokeAccount flips status to revoked -- redeem/refresh reject
// immediately after; already-issued tokens still expire naturally within
// TokenTTL unless the account's devices are also pushed onto the
// revocation list for instant cutoff (ROADMAP2 §1.4).
func (s *AccountStore) RevokeAccount(number string) error {
	res, err := s.db.Exec(
		`UPDATE accounts SET status = ? WHERE number_hash = ?`,
		StatusRevoked, hashAccountNumber(number),
	)
	if err != nil {
		return fmt.Errorf("controlplane: revoke account: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrAccountNotFound
	}
	return nil
}

func (s *AccountStore) lookup(numberHash string) (Account, error) {
	var a Account
	var status string
	var expUnix int64
	err := s.db.QueryRow(
		`SELECT id, number_hash, status, expires_at, device_limit FROM accounts WHERE number_hash = ?`,
		numberHash,
	).Scan(&a.ID, &a.NumberHash, &status, &expUnix, &a.DeviceLimit)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("controlplane: lookup account: %w", err)
	}
	a.Status = AccountStatus(status)
	a.ExpiresAt = time.Unix(expUnix, 0)
	return a, nil
}

func (a Account) checkUsable() error {
	if a.Status != StatusActive {
		return ErrAccountInactive
	}
	if time.Now().After(a.ExpiresAt) {
		return ErrAccountExpired
	}
	return nil
}

// RedeemResult is what a successful `/v1/session/redeem` hands back to the
// caller (api.go), which then signs it into a token.
type RedeemResult struct {
	Account       Account
	ShortIDHex    string
	AccountIDHash string // sha256(number_hash) -- see TokenPayload doc
}

// Redeem validates the account (active, not expired) and the device limit,
// then either reuses this device's existing short ID (idempotent re-redeem
// from the same device_pubkey, e.g. after a token refresh gap) or
// provisions a new one -- same random-shortID generation useracl.Store.Add
// uses, just persisted to SQL instead of a YAML file.
func (s *AccountStore) Redeem(number string, devicePubKeyB64 string) (RedeemResult, error) {
	numberHash := hashAccountNumber(number)
	acct, err := s.lookup(numberHash)
	if err != nil {
		return RedeemResult{}, err
	}
	if err := acct.checkUsable(); err != nil {
		return RedeemResult{}, err
	}

	accountIDHash := hashHex(numberHash)

	var existingSID string
	err = s.db.QueryRow(
		`SELECT short_id_hex FROM devices WHERE account_id = ? AND device_pub_key = ?`,
		acct.ID, devicePubKeyB64,
	).Scan(&existingSID)
	if err == nil {
		return RedeemResult{Account: acct, ShortIDHex: existingSID, AccountIDHash: accountIDHash}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return RedeemResult{}, fmt.Errorf("controlplane: lookup device: %w", err)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE account_id = ?`, acct.ID).Scan(&count); err != nil {
		return RedeemResult{}, fmt.Errorf("controlplane: count devices: %w", err)
	}
	if count >= acct.DeviceLimit {
		return RedeemResult{}, ErrDeviceLimit
	}

	sidBytes := make([]byte, 4) // auth.ShortIDLen, avoided importing internal/auth to keep this package dependency-light
	if _, err := rand.Read(sidBytes); err != nil {
		return RedeemResult{}, fmt.Errorf("controlplane: generate short id: %w", err)
	}
	shortIDHex := hex.EncodeToString(sidBytes)

	if _, err := s.db.Exec(
		`INSERT INTO devices (account_id, device_pub_key, short_id_hex, created_at) VALUES (?, ?, ?, unixepoch())`,
		acct.ID, devicePubKeyB64, shortIDHex,
	); err != nil {
		return RedeemResult{}, fmt.Errorf("controlplane: insert device: %w", err)
	}

	return RedeemResult{Account: acct, ShortIDHex: shortIDHex, AccountIDHash: accountIDHash}, nil
}

// Refresh re-validates an already-redeemed short ID's account (still
// active, not expired, not itself revoked) without touching the device
// row -- the same account/device pairing just gets a freshly signed token.
func (s *AccountStore) Refresh(shortIDHex string) (RedeemResult, error) {
	var accountID int64
	var devicePubKey string
	err := s.db.QueryRow(
		`SELECT account_id, device_pub_key FROM devices WHERE short_id_hex = ?`,
		shortIDHex,
	).Scan(&accountID, &devicePubKey)
	if errors.Is(err, sql.ErrNoRows) {
		return RedeemResult{}, ErrAccountNotFound
	}
	if err != nil {
		return RedeemResult{}, fmt.Errorf("controlplane: lookup device: %w", err)
	}

	var a Account
	var status string
	var expUnix int64
	err = s.db.QueryRow(
		`SELECT id, number_hash, status, expires_at, device_limit FROM accounts WHERE id = ?`,
		accountID,
	).Scan(&a.ID, &a.NumberHash, &status, &expUnix, &a.DeviceLimit)
	if errors.Is(err, sql.ErrNoRows) {
		return RedeemResult{}, ErrAccountNotFound
	}
	if err != nil {
		return RedeemResult{}, fmt.Errorf("controlplane: lookup account: %w", err)
	}
	a.Status = AccountStatus(status)
	a.ExpiresAt = time.Unix(expUnix, 0)
	if err := a.checkUsable(); err != nil {
		return RedeemResult{}, err
	}

	accountIDHash := hashHex(a.NumberHash)
	return RedeemResult{Account: a, ShortIDHex: shortIDHex, AccountIDHash: accountIDHash}, nil
}

// RemoveAllDevices deletes every device row for the account identified by
// number, freeing up all of its DeviceLimit slots -- e.g. an operator
// clearing stale devices (a client bug that minted a new device key on
// every launch instead of reusing one, or several lost/decommissioned
// devices) without revoking the account itself, which `RevokeAccount`
// already does and shouldn't be reused for this narrower case.
//
// Returns the short IDs that were removed so the caller can also push them
// onto the instant-revocation list (see RevocationStore.Revoke): deleting
// the device row alone does not invalidate an already-issued, still-
// unexpired token for it -- that token only stops working once its short
// ID is revoked or its TTL naturally elapses.
func (s *AccountStore) RemoveAllDevices(number string) ([]string, error) {
	acct, err := s.lookup(hashAccountNumber(number))
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`SELECT short_id_hex FROM devices WHERE account_id = ?`, acct.ID)
	if err != nil {
		return nil, fmt.Errorf("controlplane: list devices: %w", err)
	}
	var shortIDs []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			rows.Close()
			return nil, fmt.Errorf("controlplane: scan device: %w", err)
		}
		shortIDs = append(shortIDs, sid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	if _, err := s.db.Exec(`DELETE FROM devices WHERE account_id = ?`, acct.ID); err != nil {
		return nil, fmt.Errorf("controlplane: remove devices: %w", err)
	}
	return shortIDs, nil
}

// DeviceCount reports how many devices (out of DeviceLimit) an account has
// provisioned -- used by account_page.dart's "2 / 5" display once wired to
// the real API (currently mocked, see app/lib/account_store.dart).
func (s *AccountStore) DeviceCount(number string) (count, limit int, err error) {
	acct, err := s.lookup(hashAccountNumber(number))
	if err != nil {
		return 0, 0, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE account_id = ?`, acct.ID).Scan(&count); err != nil {
		return 0, 0, fmt.Errorf("controlplane: count devices: %w", err)
	}
	return count, acct.DeviceLimit, nil
}

// AccountInfoResult is what `GET /v1/account` hands back -- account-level
// display fields for account_page.dart (status/expiry/device count),
// looked up by the device's short ID (from its already-verified token)
// rather than by account number, since the number itself is never
// resubmitted after redeem.
type AccountInfoResult struct {
	Status      AccountStatus
	ExpiresAt   time.Time
	DeviceCount int
	DeviceLimit int
}

// Info looks up account-level status for the device identified by
// shortIDHex -- same device->account resolution as Refresh, but read-only.
func (s *AccountStore) Info(shortIDHex string) (AccountInfoResult, error) {
	var accountID int64
	err := s.db.QueryRow(`SELECT account_id FROM devices WHERE short_id_hex = ?`, shortIDHex).Scan(&accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountInfoResult{}, ErrAccountNotFound
	}
	if err != nil {
		return AccountInfoResult{}, fmt.Errorf("controlplane: lookup device: %w", err)
	}

	var status string
	var expUnix int64
	var deviceLimit int
	err = s.db.QueryRow(`SELECT status, expires_at, device_limit FROM accounts WHERE id = ?`, accountID).
		Scan(&status, &expUnix, &deviceLimit)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountInfoResult{}, ErrAccountNotFound
	}
	if err != nil {
		return AccountInfoResult{}, fmt.Errorf("controlplane: lookup account: %w", err)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE account_id = ?`, accountID).Scan(&count); err != nil {
		return AccountInfoResult{}, fmt.Errorf("controlplane: count devices: %w", err)
	}

	return AccountInfoResult{
		Status:      AccountStatus(status),
		ExpiresAt:   time.Unix(expUnix, 0),
		DeviceCount: count,
		DeviceLimit: deviceLimit,
	}, nil
}
