package vt

import (
	"strconv"

	"winsh/internal/textsafe"
)

// Frame rendering: turn a pair of screens into terminal octets.
//
// Two consumers need this.  The client's own console output needs the shortest
// sequence that turns what is on screen into what the server says should be on
// screen.  The SSP needs the same thing in reverse: the server's terminal diff
// is expressed as hostbytes that replay the old screen into the new one.

// RenderOptions controls what RenderFrame emits.
type RenderOptions struct {
	// Differential renders only changed cells; false repaints the screen.
	Differential bool
	// Title, when non-empty, is emitted as an OSC 0 before the frame.
	Title string
	// OmitCursor leaves the cursor untouched.  Only the local-console
	// renderer uses this; an SSP diff must always reposition the cursor, or
	// replaying it would not reproduce the sender's state.
	OmitCursor bool
}

// RenderFrame returns octets that transform old into new.  old may be nil, in
// which case the screen is fully repainted.
func RenderFrame(old, new *Screen, tx, ty int, cursorVisible bool, opts RenderOptions) []byte {
	var b []byte
	emit := func(s string) { b = append(b, s...) }
	emitBytes := func(s []byte) { b = append(b, s...) }

	if opts.Title != "" {
		emit("\x1b]0;")
		emit(sanitizeTitle(opts.Title))
		emit("\x1b\\")
	}

	full := !opts.Differential || old == nil || old.Cols != new.Cols || old.Rows != new.Rows
	// Every frame opens with a rendition reset, not just a repainting one.
	// setPen only emits an SGR when the rendition it *believes* the receiving
	// terminal is wearing changes, and that belief starts at the default.  A
	// frame that began on a terminal still wearing the last frame's colour
	// would then repaint cells with the wrong rendition, which is how
	// 24-bit backgrounds bled into the text that followed them.  Resetting up
	// front makes each frame self-contained -- which is what lets the same
	// bytes rebuild both the SSP receiver's screen and the user's console.
	emit("\x1b[0m")

	// active is the rendition currently in effect on the local terminal.
	active := Cell{}
	setPen := func(c Cell) {
		if c.FG == active.FG && c.BG == active.BG && c.Attr == active.Attr {
			return
		}
		emit(sgrSequence(c))
		active = c
	}

	for y := 0; y < new.Rows; y++ {
		nrow := new.Row(y)
		var orow []Cell
		if !full && old != nil {
			orow = old.Row(y)
		}
		x := 0
		for x < len(nrow) {
			w := unitWidth(nrow, x)
			if !full && orow != nil && unitEqual(nrow, orow, x) {
				x += w
				continue
			}
			// Collect a run of changed units so the cursor is addressed once.
			start := x
			for x < len(nrow) && (full || orow == nil || !unitEqual(nrow, orow, x)) {
				x += unitWidth(nrow, x)
			}
			emit("\x1b[")
			b = appendInt(b, y+1)
			b = append(b, ';')
			b = appendInt(b, start+1)
			emit("f")
			for cx := start; cx < x; {
				cw := unitWidth(nrow, cx)
				c := nrow[cx]
				setPen(c)
				if c.Raw == 0 || c.Raw == ' ' {
					emit(" ")
				} else {
					emitBytes(appendRune(nil, c.Raw))
					for _, m := range c.Comb {
						emitBytes(appendRune(nil, m))
					}
				}
				if cw == 2 && cx+1 < len(nrow) {
					// A wide glyph consumed two columns; make sure the
					// neighbour cannot keep a stale glyph.
					if cx+2 <= x {
						cx += 2
						continue
					}
				}
				cx += cw
			}
		}
	}
	if !opts.OmitCursor && tx >= 0 {
		if cursorVisible {
			emit("\x1b[?25h")
		} else {
			emit("\x1b[?25l")
		}
		emit("\x1b[")
		b = appendInt(b, ty+1)
		b = append(b, ';')
		b = appendInt(b, tx+1)
		emit("H")
	}
	return b
}

// unitWidth returns how many columns the cell at x occupies together with any
// wide-glyph continuation cell that belongs to it.  A WideFirst whose partner
// is not a continuation is treated as a single cell so that the partner still
// gets rendered: the emulator keeps pairs consistent, but a renderer must
// never trust that and skip content.
func unitWidth(row []Cell, x int) int {
	if x < 0 || x >= len(row) {
		return 1
	}
	if row[x].Wide == WideFirst {
		if x+1 < len(row) && row[x+1].Wide == WideCont {
			return 2
		}
		return 1
	}
	if row[x].Wide == WideCont {
		// A stray continuation cell: treat as its own unit.
		return 1
	}
	return 1
}

// unitEqual compares a whole-glyph unit between two rows, including the
// continuation half of a wide glyph.
func unitEqual(a, b []Cell, x int) bool {
	if x >= len(a) || x >= len(b) {
		return false
	}
	if !a[x].Equal(b[x]) {
		return false
	}
	if a[x].Wide == WideFirst && x+1 < len(a) {
		if x+1 >= len(b) || !a[x+1].Equal(b[x+1]) {
			return false
		}
		// A wide glyph on one side must be wide on the other.
		if b[x].Wide != WideFirst {
			return false
		}
	}
	if b[x].Wide == WideFirst && a[x].Wide != WideFirst {
		return false
	}
	return true
}

// sgrSequence renders one cell's rendition from a clean slate.
func sgrSequence(c Cell) string {
	out := []byte("\x1b[0")
	if c.Attr&AttrBold != 0 {
		out = append(out, ";1"...)
	}
	if c.Attr&AttrDim != 0 {
		out = append(out, ";2"...)
	}
	if c.Attr&AttrItalic != 0 {
		out = append(out, ";3"...)
	}
	if c.Attr&AttrUnderline != 0 {
		out = append(out, ";4"...)
	}
	if c.Attr&AttrDoubleUnderline != 0 {
		out = append(out, ";4:2"...)
	}
	if c.Attr&AttrBlink != 0 {
		out = append(out, ";5"...)
	}
	if c.Attr&AttrReverse != 0 {
		out = append(out, ";7"...)
	}
	if c.Attr&AttrHidden != 0 {
		out = append(out, ";8"...)
	}
	if c.Attr&AttrStrike != 0 {
		out = append(out, ";9"...)
	}
	if c.Attr&AttrOverline != 0 {
		out = append(out, ";53"...)
	}
	out = append(out, colorSequence("3", c.FG)...)
	out = append(out, colorSequence("4", c.BG)...)
	out = append(out, 'm')
	return string(out)
}

func colorSequence(prefix string, c Color) []byte {
	base := 30
	if prefix == "4" {
		base = 40
	}
	switch c.Kind {
	case ColorPalette:
		switch {
		case c.Palette < 8:
			return []byte(";" + strconv.Itoa(base+int(c.Palette)))
		case c.Palette < 16:
			// 90-97 and 100-107 are the bright half of the 16-colour set.
			return []byte(";" + strconv.Itoa(base+60+int(c.Palette)-8))
		default:
			return []byte(";" + prefix + "8;5;" + strconv.Itoa(int(c.Palette)))
		}
	case ColorRGB:
		return []byte(";" + prefix + "8;2;" + strconv.Itoa(int(c.R)) + ";" +
			strconv.Itoa(int(c.G)) + ";" + strconv.Itoa(int(c.B)))
	}
	if prefix == "3" {
		return []byte(";39")
	}
	return []byte(";49")
}

func sanitizeTitle(s string) string {
	return textsafe.Line(s, 1024)
}

func appendInt(b []byte, v int) []byte {
	if v < 0 {
		v = 0
	}
	return strconv.AppendInt(b, int64(v), 10)
}

func appendRune(b []byte, r rune) []byte {
	if r <= 0x7F {
		return append(b, byte(r))
	}
	if r <= 0x7FF {
		return append(b, byte(0xC0|r>>6), byte(0x80|r&0x3F))
	}
	if r <= 0xFFFF {
		return append(b, byte(0xE0|r>>12), byte(0x80|r>>6&0x3F), byte(0x80|r&0x3F))
	}
	return append(b, byte(0xF0|r>>18), byte(0x80|r>>12&0x3F), byte(0x80|r>>6&0x3F), byte(0x80|r&0x3F))
}

// DiffFull is a diagnostic switch: when set, SSP frame diffs repaint the whole
// screen instead of only the changed runs.  It is used by the test suite to
// separate run-detection bugs from rendering bugs.
var DiffFull bool
