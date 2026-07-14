package qr

import (
	"strings"
	"testing"
)

func TestRenderProducesScannableBlocks(t *testing.T) {
	var b strings.Builder
	if err := Render(&b, "chimera://1.2.3.4:443?pbk=abc&sni=h#tag"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "▀") {
		t.Error("output missing half-block glyph")
	}
	if !strings.Contains(out, reset) {
		t.Error("output missing ANSI reset (rows not terminated)")
	}
	// A QR for a real link spans many rows.
	if n := strings.Count(out, "\n"); n < 10 {
		t.Errorf("only %d rows; expected a full QR matrix", n)
	}
}

func TestRenderErrorsOnOversizeContent(t *testing.T) {
	var b strings.Builder
	// Far beyond QR capacity -> encoder must error rather than panic.
	if err := Render(&b, strings.Repeat("x", 8000)); err == nil {
		t.Error("expected error for content exceeding QR capacity")
	}
}
