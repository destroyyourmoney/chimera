package keys

import "testing"

func TestGenerateAndDecodeRoundTrip(t *testing.T) {
	priv, pub, err := GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}

	pk, err := DecodePrivate(priv)
	if err != nil {
		t.Fatalf("DecodePrivate: %v", err)
	}
	if got := EncodePublic(pk.PublicKey().Bytes()); got != pub {
		t.Fatalf("derived public %q != reported public %q", got, pub)
	}
	if _, err := DecodePublic(pub); err != nil {
		t.Fatalf("DecodePublic: %v", err)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := DecodePrivate("!!!not-base64!!!"); err == nil {
		t.Error("DecodePrivate accepted invalid base64")
	}
	if _, err := DecodePublic("AAAA"); err == nil {
		t.Error("DecodePublic accepted a wrong-length key")
	}
}
