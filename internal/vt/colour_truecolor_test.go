package vt

import (
	"fmt"
	"strings"
	"testing"
)

// TestSGRConsumesExtendedColourOperands guards the half of truecolour support
// that is easy to get wrong: 38/48 is not one parameter, it is the head of an
// operand that spans several.  Reading "38;2;r;g;b" as five independent SGR
// codes sets bold/dim/italic from r/g/b and -- because a component that is
// zero is also "reset all attributes" -- wiped the rendition back to default.
// 24-bit-color.sh paints gradients whose components are mostly zero, so the
// whole palette came out black.
func TestSGRConsumesExtendedColourOperands(t *testing.T) {
	rgb := func(r, g, b int) Color {
		return Color{Kind: ColorRGB, R: uint8(r), G: uint8(g), B: uint8(b)}
	}
	pal := func(n int) Color { return Color{Kind: ColorPalette, Palette: uint8(n)} }
	def := Color{Kind: ColorDefault}
	cases := []struct {
		name     string
		sgr      string
		wantFG   Color
		wantBG   Color
		wantAttr Attr
	}{
		{"truecolour fg", "\x1b[38;2;10;20;30m", rgb(10, 20, 30), def, 0},
		{"truecolour bg", "\x1b[48;2;10;20;30m", def, rgb(10, 20, 30), 0},
		{"zero components are a colour, not a reset", "\x1b[1;38;2;0;0;0m", rgb(0, 0, 0), def, AttrBold},
		{"bold survives a truecolour operand", "\x1b[1;38;2;1;2;3;4m", rgb(1, 2, 3), def, AttrBold | AttrUnderline},
		{"fg and bg operands in one sequence", "\x1b[38;2;1;2;3;48;2;0;0;7m", rgb(1, 2, 3), rgb(0, 0, 7), 0},
		{"256-colour operand then bold", "\x1b[38;5;196;1m", pal(196), def, AttrBold},
		{"dim after a truecolour operand", "\x1b[38;2;9;9;9;2m", rgb(9, 9, 9), def, AttrDim},
		{"explicit reset still resets", "\x1b[1;38;2;1;2;3;0m", def, def, 0},
		{"colon form", "\x1b[48:2:0:128:0m", def, rgb(0, 128, 0), 0},
		{"colon form with colour-space id", "\x1b[48:2::0:128:0m", def, rgb(0, 128, 0), 0},
		{"semicolon form with a zero red is not a colour-space id", "\x1b[38;2;0;128;0;1m", rgb(0, 128, 0), def, AttrBold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newT(20, 1)
			tr.Feed([]byte("\x1b[0m" + tc.sgr + "A"))
			c := tr.Screen().At(0, 0)
			if c.Raw != 'A' {
				t.Fatalf("cell = %+v, want the glyph to have been printed", c)
			}
			if c.FG != tc.wantFG {
				t.Errorf("fg = %+v, want %+v", c.FG, tc.wantFG)
			}
			if c.BG != tc.wantBG {
				t.Errorf("bg = %+v, want %+v", c.BG, tc.wantBG)
			}
			if c.Attr != tc.wantAttr {
				t.Errorf("attr = %v, want %v", c.Attr, tc.wantAttr)
			}
		})
	}
}

// TestConsoleReplaysColouredFrames is the property the user actually sees: a
// terminal driven only by successive rendered frames must end up displaying
// exactly what the server's screen holds, colours included.  Frames are all
// the console ever receives, so both a dropped 24-bit colour and a renderer
// that misjudges the pen it is talking to show up here as a drift.
func TestConsoleReplaysColouredFrames(t *testing.T) {
	const cols, rows = 16, 4
	console := NewTerminal(cols, rows)
	local := NewScreen(cols, rows)
	srv := NewTerminalState(cols, rows)
	steps := [][]byte{
		[]byte("\x1b[48;2;255;0;0mA"), // semicolon-form truecolour background
		[]byte("\x1b[0mB"),            // the neighbour goes back to the default pen
		[]byte("\x1b[48:2:0:0:200mC"), // colon form, which is what 24-bit-color.sh emits
		[]byte("\x1b[0m\x1b[1;1fZ"),   // repaint the red cell with no styling at all
		[]byte("\x1b[38;2;1;2;3;48;2;200;0;0mXY"),
		[]byte("\x1b[38;2;0;0;0;48;5;196mQ\x1b[0m"),
		[]byte("\x1b[1;4;38;2;7;0;0mR"),
	}
	for n, step := range steps {
		srv.Feed(step)
		x, y, visible := srv.Term.Cursor()
		frame := string(RenderFrame(local, srv.Term.Screen(), x, y, visible, RenderOptions{Differential: true}))
		if !strings.HasPrefix(frame, "\x1b[0m") {
			t.Fatalf("step %d: frame does not open with a rendition reset: %q", n, frame)
		}
		console.Feed([]byte(frame))
		local = srv.Term.Screen().Clone()
		if !console.Screen().Equal(srv.Term.Screen()) {
			t.Fatalf("step %d (%q): console drifted from the server screen\n got %s\nwant %s\nframe %q",
				n, step, describeCells(console.Screen()), describeCells(srv.Term.Screen()), frame)
		}
	}
}

// describeCells renders the styled cells of a screen for a failure message.
func describeCells(s *Screen) string {
	out := ""
	for y := 0; y < s.Rows; y++ {
		for x := 0; x < s.Cols; x++ {
			c := s.At(x, y)
			if c.IsBlank() {
				continue
			}
			out += fmt.Sprintf("[%d,%d]%q fg=%v bg=%v attr=%v ", x, y, string(c.Raw), c.FG, c.BG, c.Attr)
		}
	}
	if out == "" {
		return "(blank)"
	}
	return out
}
