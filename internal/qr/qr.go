// Package qr renders a chimera:// share link as a QR code in the terminal so a
// phone client can scan it directly, with no copy-paste of a long base64 link.
//
// Rendering uses the Unicode upper-half-block (▀) with ANSI black/white colours:
// each character encodes two vertically-stacked QR modules (foreground = top,
// background = bottom), which keeps modules roughly square and the code compact.
// Explicit black/white colours mean it scans regardless of the terminal theme.
package qr

import (
	"fmt"
	"io"

	qrcode "github.com/skip2/go-qrcode"
)

// ANSI colour codes: dark module = black, light module/quiet-zone = white.
const (
	fgBlack = "30"
	fgWhite = "37"
	bgBlack = "40"
	bgWhite = "47"
	reset   = "\033[0m"
)

// Render writes content as a terminal QR code to w. The recovery level is Medium,
// a good balance for short links scanned off a screen.
func Render(w io.Writer, content string) error {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("qr encode: %w", err)
	}
	bm := q.Bitmap() // bm[y][x] == true means a dark module; includes quiet zone
	n := len(bm)

	for y := 0; y < n; y += 2 {
		for x := 0; x < n; x++ {
			fg := fgWhite
			if bm[y][x] {
				fg = fgBlack
			}
			bg := bgWhite
			if y+1 < n && bm[y+1][x] {
				bg = bgBlack
			}
			if _, err := fmt.Fprintf(w, "\033[%s;%sm▀", fg, bg); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, reset+"\n"); err != nil {
			return err
		}
	}
	return nil
}
