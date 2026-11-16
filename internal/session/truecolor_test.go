package session_test

import (
	"fmt"
	"strings"
	"testing"

	"winsh/internal/vt"
)

// TestTruecolorGradientsReachTheConsole reproduces the 24-bit-color.sh report.
// That script paints its gradients with 48:2:r:g:b backgrounds in which most
// components are zero, so a client that reads the operand digits as SGR codes
// turns "no colour" (0) into "reset the rendition" and the gradient comes out
// black.  Everything the user sees is driven by the frames winsh renders from
// the client screen, so that screen is what has to carry the colour.
func TestTruecolorGradientsReachTheConsole(t *testing.T) {
	cl, srv, cleanup := runSession(t, false)
	defer cleanup()
	waitFor(t, "initial state exchange", func() bool { return srv.LastSentNum() > 0 })

	const bars = 60
	var b strings.Builder
	for i := 0; i < bars; i++ {
		fmt.Fprintf(&b, "\x1b[48:2:%d:0:0m ", i) // colon form, as the script emits
	}
	b.WriteString("\x1b[0m\r\n")
	for i := 0; i < bars; i++ {
		fmt.Fprintf(&b, "\x1b[48;2;0;%d;0m ", i) // semicolon form
	}
	b.WriteString("\x1b[0m\r\n")
	srv.Feed([]byte(b.String()))

	waitFor(t, "truecolour gradients on the rendered screen", func() bool {
		scr := cl.LastRendered()
		if scr == nil || scr.Rows < 2 || scr.Cols < bars {
			return false
		}
		for x := 0; x < bars; x++ {
			for y, want := range []vt.Color{
				{Kind: vt.ColorRGB, R: uint8(x)},
				{Kind: vt.ColorRGB, G: uint8(x)},
			} {
				c := scr.At(x, y)
				if c.BG != want {
					t.Logf("cell %d,%d bg = %+v, want %+v (glyph %q attr %v)", x, y, c.BG, want, string(c.Raw), c.Attr)
					return false
				}
				if c.Attr != 0 {
					t.Logf("cell %d,%d carries attributes %v left over from the colour operand", x, y, c.Attr)
					return false
				}
			}
		}
		return true
	})
}
