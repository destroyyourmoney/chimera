package qr

import (
	"fmt"
	"io"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	fgBlack = "30"
	fgWhite = "37"
	bgBlack = "40"
	bgWhite = "47"
	reset   = "\033[0m"
)

func Render(w io.Writer, content string) error {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("qr encode: %w", err)
	}
	bm := q.Bitmap()
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
