package vt

// Terminal is the emulator proper: geometry, pen, modes, and the screen
// primitives the parser calls.  All coordinates handed to a Terminal are
// clamped or ignored, so malformed control sequences from a server can move
// the display but never crash it.
type Terminal struct {
	cols, rows int

	// grid is the single cell grid.  mosh's terminal model has no
	// alternate-screen buffer: the client is driven entirely by rendered frame
	// diffs, and any state it kept that could not be reproduced by a
	// rendering would drift on every reconnect.  Taking over and restoring the
	// user's own terminal is handled by the session wrapper instead.
	grid *Screen

	x, y int

	savedX, savedY int
	savedPen       Cell

	// pen is the current graphic rendition, kept in Cell form so written
	// cells inherit it directly.
	pen Cell

	scrollTop, scrollBottom int
	charsetGL               uint8 // 'B' for ASCII, '0' for DEC special graphics
	decDrawing              bool

	origin         bool
	autowrap       bool
	wrapPending    bool
	cursorVisible  bool
	appCursor      bool
	appKeypad      bool
	bracketedPaste bool
	cursorShape    int
	inverseScreen  bool

	tabStops []bool

	title     string
	haveTitle bool

	// responses holds octets the emulator wants to send back to the host
	// (device attributes, cursor position reports).  The client normally
	// drains and discards these: the server's own terminal answers
	// applications' queries.
	responses []byte

	version uint64
	// UnknownSeqs counts control sequences that were recognised as such but
	// not implemented, for --verbose.
	UnknownSeqs int

	// lastX/lastY locate the most recently printed glyph so a combining mark
	// attaches to the right cell.
	lastX, lastY int
	haveLast     bool

	// ps is the parser's in-flight state.  It is part of the terminal so that
	// cloning a terminal also clones a partially received escape sequence or
	// UTF-8 character, exactly as the reference implementation does.
	ps parseState
}

// NewTerminal returns an 80x24 terminal in its power-on state.  Sizes are
// clamped to MaxCols/MaxRows so that no peer can request an unbounded screen.
func NewTerminal(cols, rows int) *Terminal {
	if cols < 1 {
		cols = 80
	}
	if rows < 1 {
		rows = 24
	}
	if cols > MaxCols {
		cols = MaxCols
	}
	if rows > MaxRows {
		rows = MaxRows
	}
	t := &Terminal{
		cols: cols, rows: rows,
		grid: NewScreen(cols, rows),
		pen:  BlankCell(),
		// mosh's client terminal is a display replica: autowrap on, cursor
		// shown, origin off, tabs every eight columns.
		autowrap:      true,
		cursorVisible: true,
		charsetGL:     'B',
		cursorShape:   1,
	}
	t.scrollTop = 0
	t.scrollBottom = rows - 1
	t.resetTabs()
	return t
}

// Clone returns a deep copy, suitable for storing in the SSP state window.
func (t *Terminal) Clone() *Terminal {
	n := *t
	n.grid = t.grid.Clone()
	n.tabStops = append([]bool(nil), t.tabStops...)
	n.responses = append([]byte(nil), t.responses...)
	// A snapshot is a *rendered* state, not a stream position: drop any
	// half-received escape sequence or partial UTF-8 character.  Carrying one
	// over would make replaying a frame diff flush a replacement character at
	// the wrong place, so a snapshot must start from the ground state.  This
	// mirrors the reference implementation's reset_input() on a sent state.
	n.ps = parseState{}
	return &n
}

// Screen returns the cell grid (shared storage; read-only).
func (t *Terminal) Screen() *Screen { return t.grid }

// Geometry returns the current size.
func (t *Terminal) Geometry() (cols, rows int) { return t.cols, t.rows }

// Cursor returns the cursor position and visibility.
func (t *Terminal) Cursor() (x, y int, visible bool) { return t.x, t.y, t.cursorVisible }

// Title returns the window title and whether one has been set.
func (t *Terminal) Title() (string, bool) { return t.title, t.haveTitle }

// Version bumps whenever visible state changes.
func (t *Terminal) Version() uint64 { return t.version }

// ApplicationCursor reports whether DECCKM is set, which the input layer
// needs in order to encode arrow keys.
func (t *Terminal) ApplicationCursor() bool { return t.appCursor }

// BracketedPaste reports whether mode 2004 is set.
func (t *Terminal) BracketedPaste() bool { return t.bracketedPaste }

// DrainResponses returns and clears the octets the emulator wants to send to
// the host.
func (t *Terminal) DrainResponses() []byte {
	r := t.responses
	t.responses = nil
	return r
}

func (t *Terminal) respond(s string) {
	if len(t.responses) > 4096 {
		return // a hostile server must not grow this without bound
	}
	t.responses = append(t.responses, s...)
}

// resetTabs installs the default tab stops every eight columns.
func (t *Terminal) resetTabs() {
	t.tabStops = make([]bool, t.cols)
	for x := 8; x < t.cols; x += 8 {
		t.tabStops[x] = true
	}
}

// Reset performs RIS (full reset).
func (t *Terminal) Reset() {
	cols, rows := t.cols, t.rows
	*t = *NewTerminal(cols, rows)
}

// Resize changes the geometry, reflowing by truncation as terminals do.
func (t *Terminal) Resize(cols, rows int) {
	if cols < 1 || rows < 1 {
		return
	}
	if cols > MaxCols {
		cols = MaxCols
	}
	if rows > MaxRows {
		rows = MaxRows
	}
	if cols == t.cols && rows == t.rows {
		return
	}
	t.cols, t.rows = cols, rows
	t.grid.Resize(cols, rows)
	t.scrollTop = 0
	t.scrollBottom = rows - 1
	if t.x >= cols {
		t.x = cols - 1
	}
	if t.y >= rows {
		t.y = rows - 1
	}
	if t.savedX >= cols {
		t.savedX = cols - 1
	}
	if t.savedY >= rows {
		t.savedY = rows - 1
	}
	t.resetTabs()
	t.wrapPending = false
	t.version++
}

// screen is the internal accessor used by mutating operations.
func (t *Terminal) screen() *Screen { return t.Screen() }

// clampY keeps a row inside the screen.
func (t *Terminal) clampY(y int) int {
	if y < 0 {
		return 0
	}
	if y >= t.rows {
		return t.rows - 1
	}
	return y
}

// clampX keeps a column inside the screen.
func (t *Terminal) clampX(x int) int {
	if x < 0 {
		return 0
	}
	if x >= t.cols {
		return t.cols - 1
	}
	return x
}

// moveTo positions the cursor and cancels any pending wrap.
func (t *Terminal) moveTo(x, y int) {
	t.x = t.clampX(x)
	t.y = t.clampY(y)
	t.wrapPending = false
}

// SetCursor moves the cursor absolutely (used by tests and the renderer).
func (t *Terminal) SetCursor(x, y int) { t.moveTo(x, y) }

// scrollUpWithin scrolls the current scroll region, honouring DECOM.
func (t *Terminal) scrollUp(n int) {
	t.screen().ScrollUp(t.scrollTop, t.scrollBottom, n, t.pen)
	t.version++
}

// scrollDownWithin scrolls the region down.
func (t *Terminal) scrollDown(n int) {
	t.screen().ScrollDown(t.scrollTop, t.scrollBottom, n, t.pen)
	t.version++
}

// lineFeed advances the cursor one line, scrolling at the bottom of the
// region.  This is the primitive shared by LF, IND, NEL, and autowrap.
func (t *Terminal) lineFeed() {
	if t.y == t.scrollBottom {
		t.scrollUp(1)
		return
	}
	if t.y < t.rows-1 {
		t.y++
	}
}

// reverseLineFeed moves up, scrolling down at the top of the region (RI).
func (t *Terminal) reverseLineFeed() {
	if t.y == t.scrollTop {
		t.scrollDown(1)
		return
	}
	if t.y > 0 {
		t.y--
	}
}

// mapRune applies the active GL charset to a printable code point.
func (t *Terminal) mapRune(r rune) rune {
	if !t.decDrawing {
		return r
	}
	if r >= 0x60 && r <= 0x7E {
		if m, ok := decSpecialGraphics[r]; ok {
			return m
		}
	}
	return r
}

// decSpecialGraphics is the DEC Supplemental Graphic (line-drawing) set used
// by ESC ( 0, still emitted by full-screen programs for borders.
var decSpecialGraphics = map[rune]rune{
	'`': '\u25C6', 'a': '\u2592', 'b': '\u2409', 'c': '\u240C', 'd': '\u240D',
	'e': '\u240A', 'f': '\u00B0', 'g': '\u00B1', 'h': '\u2424', 'i': '\u240B',
	'j': '\u2518', 'k': '\u2510', 'l': '\u250C', 'm': '\u2514', 'n': '\u253C',
	'o': '\u23BA', 'p': '\u23BB', 'q': '\u2500', 'r': '\u23BC', 's': '\u23BD',
	't': '\u251C', 'u': '\u2524', 'v': '\u2534', 'w': '\u252C', 'x': '\u2502',
	'y': '\u2264', 'z': '\u2265', '{': '\u03C0', '|': '\u2260', '}': '\u00A3',
	'~': '\u00B7',
}

// PutRune writes one printable character at the cursor, handling double-width
// glyphs, combining marks, and autowrap.
func (t *Terminal) PutRune(r rune) {
	if isCombining(r) {
		if !t.haveLast {
			return
		}
		t.screen().SetCombining(t.lastX, t.lastY, r)
		t.version++
		return
	}
	r = t.mapRune(r)
	w := RuneWidth(r)
	if t.autowrap && t.wrapPending {
		t.x = 0
		t.lineFeed()
		t.wrapPending = false
	}
	if w == 2 && t.x >= t.cols-1 {
		// A double-width glyph does not fit in the last column: wrap first.
		if t.autowrap {
			t.x = 0
			t.lineFeed()
		} else {
			t.x = t.clampX(t.x)
		}
	}
	if t.x >= t.cols {
		return
	}
	// Keep double-width glyphs in pairs: writing over either half of an
	// existing wide glyph erases the whole glyph, as xterm does.  Without this
	// the grid can hold a WideFirst whose partner has been overwritten, and a
	// frame diff of such a grid cannot be replayed faithfully.
	t.breakWidePairAt(t.x, t.y)
	c := t.pen
	c.Raw = r
	c.Comb = nil
	c.Wide = WideNormal
	if w == 2 {
		c.Wide = WideFirst
		t.screen().Set(t.x, t.y, c)
		if t.x+1 < t.cols {
			cont := c
			cont.Raw = 0
			cont.Wide = WideCont
			t.screen().Set(t.x+1, t.y, cont)
		}
	} else {
		t.screen().Set(t.x, t.y, c)
	}
	t.lastX, t.lastY, t.haveLast = t.x, t.y, true
	t.x += w
	if t.x >= t.cols {
		if t.autowrap {
			t.x = t.cols - 1
			t.wrapPending = true
		} else {
			t.x = t.cols - 1
		}
	}
	t.version++
}

// breakWidePairAt clears the untouched half of a wide glyph about to be
// written over.
func (t *Terminal) breakWidePairAt(x, y int) {
	switch t.screen().At(x, y).Wide {
	case WideCont:
		if x > 0 && t.screen().At(x-1, y).Wide == WideFirst {
			blank := t.pen
			blank.Raw = ' '
			blank.Comb = nil
			blank.Wide = WideNormal
			t.screen().Set(x-1, y, blank)
		}
	case WideFirst:
		if x+1 < t.cols && t.screen().At(x+1, y).Wide == WideCont {
			blank := t.pen
			blank.Raw = ' '
			blank.Comb = nil
			blank.Wide = WideNormal
			t.screen().Set(x+1, y, blank)
		}
	}
}

// isCombining reports whether r is a combining mark (a compact range test
// covering the marks that actually appear in terminal output).
func isCombining(r rune) bool {
	switch {
	case r >= 0x0300 && r <= 0x036F, // combining diacritical marks
		r >= 0x1AB0 && r <= 0x1AFF,
		r >= 0x20D0 && r <= 0x20FF, // combining marks for symbols
		r >= 0xFE00 && r <= 0xFE0F, // variation selectors
		r >= 0xFE20 && r <= 0xFE2F,
		r >= 0x1F3FB && r <= 0x1F3FF, // emoji skin-tone modifiers
		r >= 0x0591 && r <= 0x05BD:
		return true
	}
	return false
}

// Backspace moves the cursor left, cancelling any pending wrap.
func (t *Terminal) Backspace() {
	if t.wrapPending {
		t.wrapPending = false
	} else if t.x > 0 {
		t.x--
	}
}

// Tab moves to the next tab stop.
func (t *Terminal) Tab() {
	if t.x >= t.cols {
		return
	}
	for x := t.x + 1; x < t.cols; x++ {
		if x < len(t.tabStops) && t.tabStops[x] {
			t.moveTo(x, t.y)
			return
		}
	}
	t.moveTo(t.clampX(t.cols-1), t.y)
}

// CarriageReturn moves to the start of the line.
func (t *Terminal) CarriageReturn() { t.moveTo(0, t.y) }

// SetPen replaces the current graphic rendition template.
func (t *Terminal) SetPen(c Cell) { t.pen = c }

// Pen returns the current rendition template.
func (t *Terminal) Pen() Cell { return t.pen }
