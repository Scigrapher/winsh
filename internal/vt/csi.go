package vt

import "strconv"

// dispatchCSI applies one control sequence.  Unimplemented sequences are
// counted and dropped; they must never stop the byte stream.
func (t *Terminal) dispatchCSI(final byte) {
	p := &t.ps
	priv := p.private
	if priv == '?' {
		switch final {
		case 'h':
			t.setDECMode(true)
			return
		case 'l':
			t.setDECMode(false)
			return
		}
	}
	if priv == '>' {
		if final == 'c' {
			// Secondary device attributes.
			t.respond("\x1b[>0;0;0c")
			return
		}
		t.UnknownSeqs++
		return
	}
	switch final {
	case 'A':
		t.moveCursor(0, -t.pos(1, 1))
	case 'B':
		t.moveCursor(0, t.pos(1, 1))
	case 'C':
		t.moveCursor(t.pos(1, 1), 0)
	case 'D':
		t.moveCursor(-t.pos(1, 1), 0)
	case 'E':
		t.x = 0
		t.moveCursor(0, t.pos(1, 1))
	case 'F':
		t.x = 0
		t.moveCursor(0, -t.pos(1, 1))
	case 'G', '`':
		t.moveTo(t.clampX(t.pos(1, 1)-1), t.y)
	case 'd':
		t.moveTo(t.x, t.clampY(t.pos(1, 1)-1))
	case 'H', 'f':
		t.cursorPos(t.pos(1, 1), t.pos(2, 1))
	case 'I': // CHT
		n := t.pos(1, 1)
		for i := 0; i < n; i++ {
			t.Tab()
		}
		t.wrapPending = false
	case 'Z': // CBT
		n := t.pos(1, 1)
		for i := 0; i < n; i++ {
			x := t.x - 1
			for x >= 0 && (x >= len(t.tabStops) || !t.tabStops[x]) {
				x--
			}
			if x < 0 {
				x = 0
			}
			t.moveTo(x, t.y)
		}
	case 'J':
		t.screen().EraseDisplay(t.pos(1, 0), t.x, t.y, t.pen)
		t.version++
	case 'K':
		switch t.pos(1, 0) {
		case 0:
			t.screen().EraseLine(t.y, t.x, t.cols, t.pen)
		case 1:
			t.screen().EraseLine(t.y, 0, t.x+1, t.pen)
		case 2:
			t.screen().EraseLine(t.y, 0, t.cols, t.pen)
		}
		t.version++
	case 'X': // ECH
		n := t.pos(1, 1)
		if n > t.cols-t.x {
			n = t.cols - t.x
		}
		t.screen().EraseLine(t.y, t.x, t.x+n, t.pen)
		t.version++
	case '@': // ICH
		t.screen().InsertChars(t.x, t.y, t.pos(1, 1), t.pen)
		t.version++
	case 'P': // DCH
		t.screen().DeleteChars(t.x, t.y, t.pos(1, 1), t.pen)
		t.version++
	case 'L': // IL
		if t.y >= t.scrollTop && t.y <= t.scrollBottom {
			t.screen().InsertLines(t.y, t.pos(1, 1), t.scrollTop, t.scrollBottom, t.pen)
			t.version++
		}
	case 'M': // DL
		if t.y >= t.scrollTop && t.y <= t.scrollBottom {
			t.screen().DeleteLines(t.y, t.pos(1, 1), t.scrollTop, t.scrollBottom, t.pen)
			t.version++
		}
	case 'S': // SU
		t.scrollUp(t.pos(1, 1))
	case 'T': // SD
		t.scrollDown(t.pos(1, 1))
	case 'r': // DECSTBM
		top := t.pos(1, 1) - 1
		bottom := t.pos(2, t.rows) - 1
		if top < 0 {
			top = 0
		}
		if bottom >= t.rows {
			bottom = t.rows - 1
		}
		if top < bottom {
			t.scrollTop, t.scrollBottom = top, bottom
			if t.origin {
				t.moveTo(0, t.scrollTop)
			} else {
				t.moveTo(0, 0)
			}
		}
	case 's': // save cursor (SCO)
		t.savedX, t.savedY, t.savedPen = t.x, t.y, t.pen
	case 'u': // restore cursor (SCO)
		t.moveTo(t.savedX, t.savedY)
		t.pen = t.savedPen
	case 'g': // TBC
		switch t.pos(1, 0) {
		case 0:
			if t.x < len(t.tabStops) {
				t.tabStops[t.x] = false
			}
		case 3:
			for i := range t.tabStops {
				t.tabStops[i] = false
			}
		}
	case 'm':
		t.applySGR()
	case 'n': // DSR
		switch t.pos(1, 0) {
		case 5:
			t.respond("\x1b[0n")
		case 6:
			t.respond("\x1b[" + strconv.Itoa(t.y+1) + ";" + strconv.Itoa(t.x+1) + "R")
		}
	case 'c': // primary device attributes: claim a VT220-class terminal
		t.respond("\x1b[?62;22c")
	case 'q': // DECSCUSR when preceded by a space
		if len(p.interm) > 0 && p.interm[0] == ' ' {
			t.cursorShape = t.pos(1, 1)
		} else {
			t.UnknownSeqs++
		}
	case 'p':
		if len(p.interm) > 0 && p.interm[0] == '!' {
			cols, rows := t.cols, t.rows
			*t = *NewTerminal(cols, rows)
		} else {
			t.UnknownSeqs++
		}
	case 't', 'w', 'x', 'y':
		t.UnknownSeqs++
	default:
		t.UnknownSeqs++
	}
}

// pos returns parameter i (1-based) with a default, clamped to sane bounds.
func (t *Terminal) pos(i, def int) int {
	v := t.param(i, def)
	if v < 0 {
		v = 0
	}
	if v > 10000 {
		v = 10000
	}
	return v
}

// moveCursor applies a relative move, clearing the pending-wrap flag as any
// cursor addressing does.
func (t *Terminal) moveCursor(dx, dy int) {
	x, y := t.x+dx, t.y+dy
	if t.origin {
		if y < t.scrollTop {
			y = t.scrollTop
		}
		if y > t.scrollBottom {
			y = t.scrollBottom
		}
	} else {
		if y < 0 {
			y = 0
		}
		if y >= t.rows {
			y = t.rows - 1
		}
	}
	if x < 0 {
		x = 0
	}
	if x >= t.cols {
		x = t.cols - 1
	}
	t.x, t.y = x, y
	t.wrapPending = false
}

// cursorPos handles CUP/HVP, honouring origin mode.
func (t *Terminal) cursorPos(row, col int) {
	y := row - 1
	if t.origin {
		y = t.scrollTop + row - 1
		if y > t.scrollBottom {
			y = t.scrollBottom
		}
	}
	t.moveTo(t.clampX(col-1), t.clampY(y))
}

// applySGR implements Select Graphic Rendition.
func (t *Terminal) applySGR() {
	if t.nparams() == 0 {
		t.pen = BlankCell()
		t.version++
		return
	}
	for i := 1; i <= t.nparams(); i++ {
		g := t.subparams(i)
		if len(g) == 0 {
			t.pen.Attr &= ^(AttrBold | AttrDim | AttrItalic | AttrUnderline | AttrBlink |
				AttrReverse | AttrHidden | AttrStrike | AttrDoubleUnderline | AttrOverline)
			t.pen.FG = Color{Kind: ColorDefault}
			t.pen.BG = Color{Kind: ColorDefault}
			continue
		}
		code := g[0]
		switch {
		case code == 0:
			t.pen = BlankCell()
		case code == 1:
			t.pen.Attr |= AttrBold
		case code == 2:
			t.pen.Attr |= AttrDim
		case code == 3:
			t.pen.Attr |= AttrItalic
		case code == 4:
			if len(g) >= 2 && g[1] == 2 {
				t.pen.Attr |= AttrDoubleUnderline
			} else {
				t.pen.Attr |= AttrUnderline
			}
		case code == 5, code == 6:
			t.pen.Attr |= AttrBlink
		case code == 7:
			t.pen.Attr |= AttrReverse
		case code == 8:
			t.pen.Attr |= AttrHidden
		case code == 9:
			t.pen.Attr |= AttrStrike
		case code == 21:
			t.pen.Attr |= AttrDoubleUnderline
		case code == 22:
			t.pen.Attr &= ^(AttrBold | AttrDim)
		case code == 23:
			t.pen.Attr &= ^AttrItalic
		case code == 24:
			t.pen.Attr &= ^(AttrUnderline | AttrDoubleUnderline)
		case code == 25:
			t.pen.Attr &= ^AttrBlink
		case code == 27:
			t.pen.Attr &= ^AttrReverse
		case code == 28:
			t.pen.Attr &= ^AttrHidden
		case code == 29:
			t.pen.Attr &= ^AttrStrike
		case code >= 30 && code <= 37:
			t.pen.FG = Color{Kind: ColorPalette, Palette: uint8(code - 30)}
		case code == 39:
			t.pen.FG = Color{Kind: ColorDefault}
		case code >= 40 && code <= 47:
			t.pen.BG = Color{Kind: ColorPalette, Palette: uint8(code - 40)}
		case code == 49:
			t.pen.BG = Color{Kind: ColorDefault}
		case code >= 90 && code <= 97:
			t.pen.FG = Color{Kind: ColorPalette, Palette: uint8(code - 90 + 8), Intense: true}
		case code >= 100 && code <= 107:
			t.pen.BG = Color{Kind: ColorPalette, Palette: uint8(code - 100 + 8), Intense: true}
		case code == 38:
			col, used := t.extendedColor(i)
			t.pen.FG = col
			i += used - 1
		case code == 48:
			col, used := t.extendedColor(i)
			t.pen.BG = col
			i += used - 1
		case code == 53:
			t.pen.Attr |= AttrOverline
		case code == 55:
			t.pen.Attr &= ^AttrOverline
		default:
			t.UnknownSeqs++
		}
	}
	t.version++
}

// extendedColor parses the operand of an SGR 38/48 extended colour that
// starts at parameter group i (1-based).  It returns the colour *and* the
// number of parameter groups the operand occupies, which the caller must then
// skip: the operands of "38;2;r;g;b" are colour data, and reading those digits
// back as SGR codes (0=reset, 1=bold, 2=dim, 3=italic, ...) is what turned
// every truecolour cell whose components contained a zero into a reset pen.
func (t *Terminal) extendedColor(i int) (Color, int) {
	vals, grp := t.flatValuesFrom(i)
	col, nvals := parseExtendedValues(vals, func(k int) bool {
		if k < 0 || k >= len(grp) {
			return false
		}
		g := grp[k]
		return g >= 1 && g <= len(t.ps.colon) && t.ps.colon[g-1]
	})
	return col, t.groupsFor(i, nvals)
}

// flatValuesFrom flattens the parameter groups from group i (1-based) to the
// end, so that both "38;5;200" (separate parameters) and "38:5:200"
// (sub-parameters) reach the parser in one shape.  The second result pairs
// each value with the group it came from.
func (t *Terminal) flatValuesFrom(i int) ([]int, []int) {
	var vals []int
	var grp []int
	for g := i; g <= t.nparams(); g++ {
		for _, v := range t.subparams(g) {
			vals = append(vals, v)
			grp = append(grp, g)
		}
	}
	return vals, grp
}

// groupsFor converts a count of consumed values into the count of parameter
// groups they span, starting at group i.  Values are never left half
// consumed: whatever is left over belongs to the operand and is skipped.
func (t *Terminal) groupsFor(i, nvals int) int {
	if nvals <= 0 {
		return 1
	}
	seen := 0
	for g := i; g <= t.nparams(); g++ {
		seen += len(t.subparams(g))
		if seen >= nvals {
			return g - i + 1
		}
	}
	return t.nparams() - i + 1
}

// parseExtendedValues decodes the operand of SGR 38/48 -- "5;n", "2;r;g;b" and
// their colon forms -- from the flattened value list that begins with the 38
// or 48 itself.  colon(k) reports whether the k-th value belongs to a group
// written with ":" separators, which is how the 38:2::<colour-space>:r:g:b
// form is told apart from a 38;2;0;r;g;b whose red really is zero.  It
// returns the colour and how many values it consumed; a malformed operand
// swallows the rest of the sequence, because the leftovers are colour data
// rather than rendition codes.
func parseExtendedValues(vals []int, colon func(k int) bool) (Color, int) {
	if len(vals) < 2 {
		return Color{Kind: ColorDefault}, len(vals)
	}
	switch vals[1] {
	case 5:
		if len(vals) < 3 {
			return Color{Kind: ColorDefault}, len(vals)
		}
		return Color{Kind: ColorPalette, Palette: uint8(vals[2] & 0xFF)}, 3
	case 2:
		off, used := 2, 5
		// The colon form may carry a colour-space id between the 2 and the
		// components; the parser records that empty field as a zero.
		if len(vals) >= 6 && vals[2] == 0 && colon(2) {
			off, used = 3, 6
		}
		if len(vals) < off+3 {
			return Color{Kind: ColorDefault}, len(vals)
		}
		clamp := func(v int) uint8 {
			if v < 0 {
				return 0
			}
			if v > 255 {
				return 255
			}
			return uint8(v)
		}
		return Color{Kind: ColorRGB, R: clamp(vals[off]), G: clamp(vals[off+1]),
			B: clamp(vals[off+2])}, used
	}
	return Color{Kind: ColorDefault}, len(vals)
}

// setDECMode implements the DEC private modes that affect what the user sees.
// Modes we do not honour are recorded so that the input layer can still
// behave correctly (for example application cursor keys change what bytes the
// arrow keys produce).
func (t *Terminal) setDECMode(on bool) {
	for i := 1; i <= t.nparams(); i++ {
		switch t.param(i, 0) {
		case 1: // DECCKM
			t.appCursor = on
		case 6: // DECOM
			t.origin = on
			if on {
				t.moveTo(0, t.scrollTop)
			} else {
				t.moveTo(0, 0)
			}
		case 7: // DECAWM
			t.autowrap = on
			t.wrapPending = false
		case 12: // cursor blink: cosmetic
		case 25: // DECTCEM
			t.cursorVisible = on
		case 59, 66: // numeric/keypad application
			t.appKeypad = on
		case 1000, 1002, 1003, 1005, 1006, 1015, 1016: // mouse reporting
			// Recorded, not acted on: winsh never synthesises mouse reports.
		case 2004: // bracketed paste
			t.bracketedPaste = on
		case 47, 1047, 1049:
			// Alternate screen: accepted and ignored, matching the reference
			// implementation's single-buffer model.  The application redraws
			// whatever it wants visible, so nothing is lost.
		case 1034, 1036, 1037: // meta key modes: ignored
		case 2026: // synchronous output: cosmetic
		default:
			t.UnknownSeqs++
		}
	}
	t.version++
}
