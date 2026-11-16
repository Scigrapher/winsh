package vt

import (
	"strings"
	"testing"
)

// The emulator parses 38;2;r;g;b already; this checks the other half -- that a
// 24-bit colour survives the trip back out to the console instead of being
// flattened to the palette, which is what made colours look wrong even though
// the parser was correct.
func TestRenderPreserves24BitColor(t *testing.T) {
	tr := newT(20, 4)
	tr.Feed([]byte("\x1b[0m\x1b[38;2;17;200;5mred\x1b[0m"))
	c := tr.Screen().At(0, 0)
	if c.FG.Kind != ColorRGB || c.FG.R != 17 || c.FG.G != 200 || c.FG.B != 5 {
		t.Fatalf("parsed fg = %+v, want rgb(17,200,5)", c.FG)
	}

	frame := string(RenderFrame(NewScreen(20, 4), tr.Screen(), 0, 0, true, RenderOptions{}))
	if !strings.Contains(frame, "38;2;17;200;5") {
		t.Errorf("rendered frame lost the 24-bit colour:\n%q", frame)
	}
	if strings.Contains(frame, "38;5;") {
		t.Errorf("24-bit colour was downgraded to the 256-colour palette:\n%q", frame)
	}

	tr.Feed([]byte("\x1b[0m\x1b[48;2;250;1;254mx"))
	frame = string(RenderFrame(NewScreen(20, 4), tr.Screen(), 0, 0, true, RenderOptions{}))
	if !strings.Contains(frame, "48;2;250;1;254") {
		t.Errorf("24-bit background not emitted:\n%q", frame)
	}
}

// TestRenderNoOpWhenUnchanged guards against the repaint firehose: an idle
// screen must not generate console output on every pass.
func TestRenderNoOpWhenUnchanged(t *testing.T) {
	tr := newT(20, 4)
	tr.Feed([]byte("hello\r\n"))
	before := tr.Screen().Clone()
	frame := string(RenderFrame(before, tr.Screen(), 0, 0, true, RenderOptions{Differential: true}))
	// A differential frame against an unchanged screen must not repaint cells.
	// It may still re-assert the cursor, because cursor state lives on the
	// Terminal rather than the Screen and so is not comparable here; the
	// session loop is what avoids calling render at all when nothing moved.
	if strings.Contains(frame, "hello") {
		t.Errorf("unchanged screen had its cells repainted: %q", frame)
	}
	for _, frag := range strings.Split(frame, "\x1b[") {
		if strings.Contains(frag, ";1f") || strings.Contains(frag, ";1F") {
			t.Errorf("unchanged screen emitted row positioning (a full repaint): %q", frame)
			break
		}
	}
	if len(frame) > 32 {
		t.Errorf("unchanged screen produced %d bytes, expected only a cursor tail: %q", len(frame), frame)
	}
}
