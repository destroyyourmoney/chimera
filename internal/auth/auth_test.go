package auth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

// handshake returns a fresh client ephemeral key, the server static key, and the
// shared secret as both sides would compute it.
func handshake(t *testing.T) (eph *ecdh.PrivateKey, srv *ecdh.PrivateKey, ss []byte) {
	t.Helper()
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	srv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("srv keygen: %v", err)
	}
	ss, err = eph.ECDH(srv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return eph, srv, ss
}

func TestSealOpenRoundTrip(t *testing.T) {
	eph, srv, ss := handshake(t)
	shortID := []byte{0x0a, 0x1b, 0x2c, 0x3d}

	tag, err := Seal(ss, eph.PublicKey().Bytes(), srv.PublicKey().Bytes(), shortID)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(tag) != TagLen {
		t.Fatalf("tag len = %d, want %d", len(tag), TagLen)
	}

	// Server recomputes ss from its private key and the client's key_share.
	srvSS, err := srv.ECDH(eph.PublicKey())
	if err != nil {
		t.Fatalf("server ecdh: %v", err)
	}
	got, ok := Open(srvSS, eph.PublicKey().Bytes(), srv.PublicKey().Bytes(), tag)
	if !ok {
		t.Fatal("Open rejected a valid tag")
	}
	if !bytes.Equal(got, shortID) {
		t.Fatalf("shortID = %x, want %x", got, shortID)
	}
}

func TestOpenRejectsTamperedTag(t *testing.T) {
	eph, srv, ss := handshake(t)
	tag, _ := Seal(ss, eph.PublicKey().Bytes(), srv.PublicKey().Bytes(), []byte{1, 2, 3, 4})

	for i := range tag {
		bad := bytes.Clone(tag)
		bad[i] ^= 0x01
		if _, ok := Open(ss, eph.PublicKey().Bytes(), srv.PublicKey().Bytes(), bad); ok {
			t.Fatalf("Open accepted a tag with byte %d flipped", i)
		}
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	eph, srv, ss := handshake(t)
	tag, _ := Seal(ss, eph.PublicKey().Bytes(), srv.PublicKey().Bytes(), []byte{1, 2, 3, 4})

	// An attacker without the server private key derives a different ss.
	wrong, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongSS, _ := eph.ECDH(wrong.PublicKey())
	if _, ok := Open(wrongSS, eph.PublicKey().Bytes(), srv.PublicKey().Bytes(), tag); ok {
		t.Fatal("Open accepted a tag verified against the wrong shared secret")
	}
}

func TestOpenReplayWindow(t *testing.T) {
	eph, srv, ss := handshake(t)
	cpub, spub := eph.PublicKey().Bytes(), srv.PublicKey().Bytes()

	base := time.Unix(1_700_000_000, 0)
	withClock(t, func() time.Time { return base })
	tag, _ := Seal(ss, cpub, spub, []byte{1, 2, 3, 4})

	// Same window: accepted.
	if _, ok := Open(ss, cpub, spub, tag); !ok {
		t.Fatal("tag rejected within its own window")
	}

	// One window of skew: accepted (clock tolerance).
	withClock(t, func() time.Time { return base.Add(windowSeconds * time.Second) })
	if _, ok := Open(ss, cpub, spub, tag); !ok {
		t.Fatal("tag rejected at +1 window (should tolerate skew)")
	}

	// Far in the future: fail-closed (replay after the window).
	withClock(t, func() time.Time { return base.Add(10 * windowSeconds * time.Second) })
	if _, ok := Open(ss, cpub, spub, tag); ok {
		t.Fatal("stale tag accepted — replay window not enforced")
	}
}

// withClock swaps the package clock for the duration of the test.
func withClock(t *testing.T, fn func() time.Time) {
	t.Helper()
	prev := nowFunc
	nowFunc = fn
	t.Cleanup(func() { nowFunc = prev })
}
