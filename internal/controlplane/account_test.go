package controlplane

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestGenerateAccountNumberFormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n, err := GenerateAccountNumber()
		if err != nil {
			t.Fatalf("GenerateAccountNumber: %v", err)
		}
		parts := strings.Split(n, "-")
		if len(parts) != 4 {
			t.Fatalf("expected 4 groups, got %d in %q", len(parts), n)
		}
		for _, p := range parts {
			if len(p) != 4 {
				t.Fatalf("expected group length 4, got %q in %q", p, n)
			}
			for _, c := range p {
				if !strings.ContainsRune(keyAlphabet, c) {
					t.Fatalf("char %q not in keyAlphabet (number %q)", c, n)
				}
			}
		}
		if seen[n] {
			t.Fatalf("duplicate account number generated: %q", n)
		}
		seen[n] = true
	}
}

func TestCreateAccountStoresHashNotNumber(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)

	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	var raw string
	if err := db.QueryRow(`SELECT number_hash FROM accounts`).Scan(&raw); err != nil {
		t.Fatalf("query number_hash: %v", err)
	}
	if raw == number || strings.Contains(raw, "-") {
		t.Fatalf("number_hash looks like the plaintext number: %q", raw)
	}
	if raw != hashAccountNumber(number) {
		t.Fatalf("stored hash does not match hashAccountNumber(number)")
	}
}

func TestRedeemValidAccount(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	devicePub := base64.StdEncoding.EncodeToString([]byte("device-key-1"))
	res, err := store.Redeem(number, devicePub)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if len(res.ShortIDHex) != 8 {
		t.Fatalf("expected 8 hex chars short id, got %q", res.ShortIDHex)
	}

	res2, err := store.Redeem(number, devicePub)
	if err != nil {
		t.Fatalf("second Redeem: %v", err)
	}
	if res2.ShortIDHex != res.ShortIDHex {
		t.Fatalf("expected idempotent short id, got %q vs %q", res2.ShortIDHex, res.ShortIDHex)
	}
}

func TestRedeemInvalidAccount(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	_, err := store.Redeem("XXXX-XXXX-XXXX-XXXX", "device")
	if !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("expected ErrAccountNotFound, got %v", err)
	}
}

func TestRedeemExpiredAccount(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(-time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	_, err = store.Redeem(number, "device")
	if !errors.Is(err, ErrAccountExpired) {
		t.Fatalf("expected ErrAccountExpired, got %v", err)
	}
}

func TestRedeemRevokedAccount(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := store.RevokeAccount(number); err != nil {
		t.Fatalf("RevokeAccount: %v", err)
	}
	_, err = store.Redeem(number, "device")
	if !errors.Is(err, ErrAccountInactive) {
		t.Fatalf("expected ErrAccountInactive, got %v", err)
	}
}

func TestRedeemDeviceLimit(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 2)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if _, err := store.Redeem(number, "device-1"); err != nil {
		t.Fatalf("Redeem device-1: %v", err)
	}
	if _, err := store.Redeem(number, "device-2"); err != nil {
		t.Fatalf("Redeem device-2: %v", err)
	}
	if _, err := store.Redeem(number, "device-3"); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("expected ErrDeviceLimit for 3rd device, got %v", err)
	}
}

func TestRefreshRejectsRevokedAccount(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	res, err := store.Redeem(number, "device-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if _, err := store.Refresh(res.ShortIDHex); err != nil {
		t.Fatalf("Refresh before revoke: %v", err)
	}
	if err := store.RevokeAccount(number); err != nil {
		t.Fatalf("RevokeAccount: %v", err)
	}
	if _, err := store.Refresh(res.ShortIDHex); !errors.Is(err, ErrAccountInactive) {
		t.Fatalf("expected ErrAccountInactive after revoke, got %v", err)
	}
}

func TestAccountInfoByShortID(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 3)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	res, err := store.Redeem(number, "device-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	info, err := store.Info(res.ShortIDHex)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Status != StatusActive || info.DeviceCount != 1 || info.DeviceLimit != 3 {
		t.Fatalf("unexpected info: %+v", info)
	}

	if _, err := store.Info("nonexistent"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("expected ErrAccountNotFound for unknown short id, got %v", err)
	}
}

func TestRemoveAllDevices(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 2)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	res1, err := store.Redeem(number, "device-1")
	if err != nil {
		t.Fatalf("Redeem device-1: %v", err)
	}
	res2, err := store.Redeem(number, "device-2")
	if err != nil {
		t.Fatalf("Redeem device-2: %v", err)
	}

	shortIDs, err := store.RemoveAllDevices(number)
	if err != nil {
		t.Fatalf("RemoveAllDevices: %v", err)
	}
	if len(shortIDs) != 2 {
		t.Fatalf("expected 2 removed short IDs, got %+v", shortIDs)
	}
	got := map[string]bool{shortIDs[0]: true, shortIDs[1]: true}
	if !got[res1.ShortIDHex] || !got[res2.ShortIDHex] {
		t.Fatalf("removed short IDs %+v don't match redeemed %q/%q", shortIDs, res1.ShortIDHex, res2.ShortIDHex)
	}

	count, limit, err := store.DeviceCount(number)
	if err != nil {
		t.Fatalf("DeviceCount: %v", err)
	}
	if count != 0 || limit != 2 {
		t.Fatalf("expected 0/2 after removal, got %d/%d", count, limit)
	}

	if _, err := store.Redeem(number, "device-3"); err != nil {
		t.Fatalf("expected the account to still accept a fresh redeem after RemoveAllDevices: %v", err)
	}
}

func TestRemoveAllDevicesUnknownAccount(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	if _, err := store.RemoveAllDevices("0000-0000-0000-0000"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("expected ErrAccountNotFound, got %v", err)
	}
}

func TestRemoveAllDevicesOnAccountWithNoDevices(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	shortIDs, err := store.RemoveAllDevices(number)
	if err != nil {
		t.Fatalf("RemoveAllDevices: %v", err)
	}
	if len(shortIDs) != 0 {
		t.Fatalf("expected no devices removed, got %+v", shortIDs)
	}
}

func TestDeviceCount(t *testing.T) {
	db := newTestDB(t)
	store := NewAccountStore(db)
	number, err := store.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if _, err := store.Redeem(number, "device-1"); err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	count, limit, err := store.DeviceCount(number)
	if err != nil {
		t.Fatalf("DeviceCount: %v", err)
	}
	if count != 1 || limit != 5 {
		t.Fatalf("expected 1/5, got %d/%d", count, limit)
	}
}
