package vt

import (
	"math/rand"
	"strings"
	"testing"

	"winsh/internal/stream"
)

func newT(cols, rows int) *Terminal { return NewTerminal(cols, rows) }

func dumpRows(tr *Terminal) []string {
	s := tr.Screen()
	out := make([]string, s.Rows)
	for y := 0; y < s.Rows; y++ {
		out[y] = s.RowString(y)
	}
	return out
}

func wantRows(t *testing.T, tr *Terminal, want ...string) {
	t.Helper()
	got := dumpRows(tr)
	for i := range want {
		if i >= len(got) {
			t.Fatalf("row %d missing; have %d rows", i, len(got))
		}
		if got[i] != want[i] {
			t.Fatalf("row %d = %q, want %q (all: %q)", i, got[i], want[i], got)
		}
	}
}

func TestPrintAndWrap(t *testing.T) {
	tr := newT(10, 3)
	tr.Feed([]byte("hello world!"))
	wantRows(t, tr, "hello worl", "d!")
	if x, y, _ := tr.Cursor(); x != 2 || y != 1 {
		t.Fatalf("cursor = %d,%d want 2,1", x, y)
	}
}

// TestNoWrapOverwritesRightMargin documents DECAWM off: the cursor sticks at
// the right margin and further characters overwrite that one cell.
func TestNoWrapOverwritesRightMargin(t *testing.T) {
	tr := newT(5, 2)
	tr.Feed([]byte("\x1b[?7l"))
	tr.Feed([]byte("abcdef"))
	wantRows(t, tr, "abcdf")
	if x, _, _ := tr.Cursor(); x != 4 {
		t.Fatalf("cursor x = %d, want clamped 4", x)
	}
}

func TestCursorAddressing(t *testing.T) {
	tr := newT(20, 5)
	tr.Feed([]byte("\x1b[3;5HXY"))
	wantRows(t, tr, "", "", "    XY")
	tr.Feed([]byte("\x1b[A")) // CUU 1
	if x, y, _ := tr.Cursor(); x != 6 || y != 1 {
		t.Fatalf("after CUU cursor = %d,%d want 6,1", x, y)
	}
	tr.Feed([]byte("\x1b[2d")) // VPA to row 2
	if _, y, _ := tr.Cursor(); y != 1 {
		t.Fatalf("VPA y = %d want 1", y)
	}
	tr.Feed([]byte("\x1b[7G")) // CHA
	if x, _, _ := tr.Cursor(); x != 6 {
		t.Fatalf("CHA x = %d want 6", x)
	}
	tr.Feed([]byte("\x1b[3C\x1b[2D"))
	if x, _, _ := tr.Cursor(); x != 7 {
		t.Fatalf("CUF/CUB x = %d want 7", x)
	}
	tr.Feed([]byte("\x1b[2;1HX"))
	wantRows(t, tr, "", "X", "    XY")
}

func TestEraseLineModes(t *testing.T) {
	tr := newT(10, 3)
	tr.Feed([]byte("aaaaaaaaaa\r\nbbbbbbbbbb\r\ncccccccccc"))
	tr.Feed([]byte("\x1b[2;3H\x1b[0K"))
	wantRows(t, tr, "aaaaaaaaaa", "bb", "cccccccccc")
	tr.Feed([]byte("\x1b[3;1H\x1b[1K"))
	wantRows(t, tr, "aaaaaaaaaa", "bb", " ccccccccc")
	tr.Feed([]byte("\x1b[3;1H\x1b[2K"))
	wantRows(t, tr, "aaaaaaaaaa", "bb", "")
}

func TestEraseDisplay(t *testing.T) {
	tr := newT(6, 3)
	tr.Feed([]byte("aaaaaa\r\nbbbbbb\r\ncccccc"))
	tr.Feed([]byte("\x1b[2;3H\x1b[1J"))
	wantRows(t, tr, "", "   bbb", "cccccc")
	tr.Feed([]byte("\x1b[3J"))
	wantRows(t, tr, "", "   bbb", "cccccc")
	tr.Feed([]byte("\x1b[2J"))
	wantRows(t, tr, "", "", "")
}

func TestScrollRegionBounds(t *testing.T) {
	tr := newT(5, 5)
	tr.Feed([]byte("l1\r\nl2\r\nl3\r\nl4\r\nl5"))
	tr.Feed([]byte("\x1b[2;4r"))
	if tr.scrollTop != 1 || tr.scrollBottom != 3 {
		t.Fatalf("region = %d..%d want 1..3", tr.scrollTop, tr.scrollBottom)
	}
	tr.Feed([]byte("\x1b[1;1HX\r\nY\r\nZ\r\nW"))
	wantRows(t, tr, "X1", "Y2", "Z3", "W4", "l5")
	// LF at the region bottom scrolls only the region; line 5 is untouched.
	tr.Feed([]byte("\x1b[4;1H\r\n"))
	wantRows(t, tr, "X1", "Z3", "W4", "", "l5")
}

func TestScrollUpAtRegionBottom(t *testing.T) {
	tr := newT(5, 4)
	tr.Feed([]byte("a\r\nb\r\nc\r\nd"))
	tr.Feed([]byte("\x1b[2;3r\x1b[3;1Hz\r\n"))
	wantRows(t, tr, "a", "z", "", "d")
}

func TestReverseIndexAtRegionTop(t *testing.T) {
	tr := newT(5, 4)
	tr.Feed([]byte("a\r\nb\r\nc\r\nd"))
	tr.Feed([]byte("\x1b[2;3r\x1b[2;1H"))
	tr.Feed([]byte("\x1bM")) // RI at region top scrolls the region down
	wantRows(t, tr, "a", "", "b", "d")
}

func TestInsertDeleteLines(t *testing.T) {
	tr := newT(5, 4)
	tr.Feed([]byte("a\r\nb\r\nc\r\nd"))
	tr.Feed([]byte("\x1b[2;1H\x1b[1L"))
	wantRows(t, tr, "a", "", "b", "c")
	tr.Feed([]byte("\x1b[2;1H\x1b[1M"))
	wantRows(t, tr, "a", "b", "c", "")
}

func TestInsertDeleteChars(t *testing.T) {
	tr := newT(8, 1)
	tr.Feed([]byte("abcdefg"))
	tr.Feed([]byte("\x1b[1;3H\x1b[2@"))
	wantRows(t, tr, "ab  cdef")
	tr.Feed([]byte("\x1b[1;1H\x1b[2P"))
	wantRows(t, tr, "  cdef")
}

func TestTabs(t *testing.T) {
	tr := newT(24, 1)
	tr.Feed([]byte("\tX\tY"))
	wantRows(t, tr, "        X       Y")
	tr.Feed([]byte("\x1b[1;1H\x1b[3g\tZ"))
	if got := dumpRows(tr)[0]; !strings.HasSuffix(got, "Z") {
		t.Fatalf("with no tab stops, a tab must reach the right margin: %q", got)
	}
}

func TestSaveRestoreCursor(t *testing.T) {
	tr := newT(10, 4)
	tr.Feed([]byte("\x1b[3;4H\x1b7\x1b[1;1Habc\x1b8"))
	if x, y, _ := tr.Cursor(); x != 3 || y != 2 {
		t.Fatalf("after DECRC cursor = %d,%d want 3,2", x, y)
	}
	tr.Feed([]byte("\x1b[4;5H\x1b[s\x1b[1;1H\x1b[u"))
	if x, y, _ := tr.Cursor(); x != 4 || y != 3 {
		t.Fatalf("after SCP/PRP cursor = %d,%d want 4,3", x, y)
	}
}

func TestSGRColors(t *testing.T) {
	tr := newT(10, 1)
	tr.Feed([]byte("\x1b[1;31;44mA"))
	c := tr.Screen().At(0, 0)
	if c.Raw != 'A' || c.Attr&AttrBold == 0 {
		t.Fatalf("cell = %+v", c)
	}
	if c.FG.Kind != ColorPalette || c.FG.Palette != 1 {
		t.Fatalf("fg = %+v want palette 1", c.FG)
	}
	if c.BG.Kind != ColorPalette || c.BG.Palette != 4 {
		t.Fatalf("bg = %+v want palette 4", c.BG)
	}
	tr.Feed([]byte("\x1b[0m\x1b[38;5;200mB"))
	c = tr.Screen().At(1, 0)
	if c.FG.Kind != ColorPalette || c.FG.Palette != 200 {
		t.Fatalf("256-colour fg = %+v want palette 200", c.FG)
	}
	tr.Feed([]byte("\x1b[0m\x1b[48;2;10;20;30mC"))
	c = tr.Screen().At(2, 0)
	if c.BG.Kind != ColorRGB || c.BG.R != 10 || c.BG.G != 20 || c.BG.B != 30 {
		t.Fatalf("truecolour bg = %+v", c.BG)
	}
	tr.Feed([]byte("\x1b[0m\x1b[38:2::1:2:3mD"))
	c = tr.Screen().At(3, 0)
	if c.FG.Kind != ColorRGB || c.FG.R != 1 || c.FG.G != 2 || c.FG.B != 3 {
		t.Fatalf("colon-form truecolour fg = %+v", c.FG)
	}
	tr.Feed([]byte("\x1b[0m\x1b[38:5:42mE"))
	c = tr.Screen().At(4, 0)
	if c.FG.Kind != ColorPalette || c.FG.Palette != 42 {
		t.Fatalf("colon-form 256 fg = %+v", c.FG)
	}
	tr.Feed([]byte("\x1b[0m\x1b[91mF"))
	c = tr.Screen().At(5, 0)
	if c.FG.Kind != ColorPalette || c.FG.Palette != 9 {
		t.Fatalf("bright fg = %+v want palette 9", c.FG)
	}
	tr.Feed([]byte("\x1b[0;4;9mG"))
	c = tr.Screen().At(6, 0)
	if c.Attr&(AttrUnderline|AttrStrike) != (AttrUnderline | AttrStrike) {
		t.Fatalf("underline+strike = %v", c.Attr)
	}
	if c.FG.Kind != ColorDefault {
		t.Fatalf("SGR 0 must reset colours, got %+v", c.FG)
	}
}

func TestModes(t *testing.T) {
	tr := newT(10, 3)
	tr.Feed([]byte("\x1b[?25l"))
	if _, _, v := tr.Cursor(); v {
		t.Fatalf("cursor should be hidden")
	}
	tr.Feed([]byte("\x1b[?25h"))
	if _, _, v := tr.Cursor(); !v {
		t.Fatalf("cursor should be visible")
	}
	tr.Feed([]byte("\x1b[?1h"))
	if !tr.ApplicationCursor() {
		t.Fatalf("DECCKM not set")
	}
	tr.Feed([]byte("\x1b[?2004h"))
	if !tr.BracketedPaste() {
		t.Fatalf("bracketed paste not set")
	}
	// Origin mode: CUP is relative to the scroll region.
	tr2 := newT(10, 6)
	tr2.Feed([]byte("\x1b[3;5r\x1b[?6h\x1b[1;1HZ"))
	wantRows(t, tr2, "", "", "Z", "", "", "")
	tr.Feed([]byte("\x1b[?6l\x1b[?1l\x1b[?2004l"))
}

func TestDECSpecialGraphics(t *testing.T) {
	tr := newT(8, 1)
	tr.Feed([]byte("\x1b(0lqqk\x1b(B"))
	got := tr.Screen().RowString(0)
	if want := "\u250c\u2500\u2500\u2510"; got != want {
		t.Fatalf("dec drawing = %q, want %q", got, want)
	}
}

func TestUTF8(t *testing.T) {
	tr := newT(20, 2)
	tr.Feed([]byte("a\u00e9\u20ac"))
	if s := tr.Screen().RowString(0); s != "a\u00e9\u20ac" {
		t.Fatalf("utf8 = %q", s)
	}
	// Split a multi-byte sequence across Feed calls.
	tr2 := newT(20, 2)
	tr2.Feed([]byte("x\xe2"))
	tr2.Feed([]byte("\x82"))
	tr2.Feed([]byte("\xac"))
	if s := tr2.Screen().RowString(0); s != "x\u20ac" {
		t.Fatalf("split utf8 = %q", s)
	}
	// A 4-byte sequence (astral plane).
	tr4 := newT(20, 2)
	tr4.Feed([]byte("\xf0\x9f\x98\x80"))
	if s := tr4.Screen().RowString(0); s != "\U0001F600" {
		t.Fatalf("astral utf8 = %q", s)
	}
	// Invalid lead byte becomes the replacement character.
	tr3 := newT(20, 2)
	tr3.Feed([]byte{'\xff', 'A'})
	if s := tr3.Screen().RowString(0); s != "\uFFFDA" {
		t.Fatalf("invalid utf8 = %q", s)
	}
	// Truncated sequence followed by ASCII flushes a replacement first.
	tr5 := newT(20, 2)
	tr5.Feed([]byte{'\xe2', 'A'})
	if s := tr5.Screen().RowString(0); s != "\uFFFDA" {
		t.Fatalf("truncated utf8 = %q", s)
	}
}

func TestCombiningMarks(t *testing.T) {
	tr := newT(10, 1)
	tr.Feed([]byte("e\u0301x"))
	c := tr.Screen().At(0, 0)
	if c.Raw != 'e' || len(c.Comb) != 1 || c.Comb[0] != 0x0301 {
		t.Fatalf("combining = %+v", c)
	}
	if s := tr.Screen().RowString(0); s != "ex" {
		t.Fatalf("row = %q", s)
	}
	// A combining mark with no preceding glyph is dropped, not written into
	// the cell the cursor happens to sit on.
	tr2 := newT(10, 1)
	tr2.Feed([]byte("\x1b[1;3H\u0301"))
	if len(tr2.Screen().At(2, 0).Comb) != 0 {
		t.Fatalf("stray combining mark was stored")
	}
	// Beyond the cap they are dropped rather than growing without bound.
	tr3 := newT(10, 1)
	tr3.Feed([]byte("a"))
	for i := 0; i < maxCombining+20; i++ {
		tr3.Feed([]byte("\u0301"))
	}
	if len(tr3.Screen().At(0, 0).Comb) != maxCombining {
		t.Fatalf("combining cap = %d", len(tr3.Screen().At(0, 0).Comb))
	}
}

func TestWideChars(t *testing.T) {
	tr := newT(10, 2)
	tr.Feed([]byte("\u6f22\u5b57"))
	c0 := tr.Screen().At(0, 0)
	c1 := tr.Screen().At(1, 0)
	if c0.Wide != WideFirst || c1.Wide != WideCont {
		t.Fatalf("wide flags = %d %d", c0.Wide, c1.Wide)
	}
	if x, _, _ := tr.Cursor(); x != 4 {
		t.Fatalf("cursor after two wide glyphs = %d want 4", x)
	}
	tr2 := newT(3, 2)
	tr2.Feed([]byte("ab\u6f22"))
	if tr2.Screen().RowString(0) != "ab" || tr2.Screen().RowString(1) != "\u6f22" {
		t.Fatalf("wrap = %q", dumpRows(tr2))
	}
	// Replacing a wide glyph with two narrow ones must clear both cells.
	tr3 := newT(4, 1)
	tr3.Feed([]byte("\x1b[1;1H\u6f22"))
	tr3.Feed([]byte("\x1b[1;1Hxy"))
	if got := tr3.Screen().RowString(0); got != "xy" {
		t.Fatalf("stale wide continuation = %q", got)
	}
}

func TestOSCSetTitleAndSanitizes(t *testing.T) {
	tr := newT(10, 1)
	tr.Feed([]byte("\x1b]0;hello\x07"))
	tr.Feed([]byte("\x1b]2;second\x1b\\"))
	title, ok := tr.Title()
	if !ok || title != "second" {
		t.Fatalf("title = %q ok=%v", title, ok)
	}
	tr.Feed([]byte("\x1b]0;bad\x1b[31mtitle\x07"))
	title, _ = tr.Title()
	if strings.ContainsAny(title, "\x1b\x07") {
		t.Fatalf("unsanitised title = %q", title)
	}
}

func TestOSC52Ignored(t *testing.T) {
	tr := newT(10, 1)
	tr.Feed([]byte("\x1b]52;c;AAAA\x07"))
	if _, ok := tr.Title(); ok {
		t.Fatalf("OSC 52 must not affect visible state")
	}
	if len(tr.DrainResponses()) != 0 {
		t.Fatalf("OSC 52 must not produce host output")
	}
}

func TestResizeClamped(t *testing.T) {
	tr := newT(10, 5)
	tr.Resize(100000, 100000)
	cols, rows := tr.Geometry()
	if cols != MaxCols || rows != MaxRows {
		t.Fatalf("clamped geometry = %dx%d, want %dx%d", cols, rows, MaxCols, MaxRows)
	}
	if s := NewTerminalState(100000, 100000); s.Term.Screen().Cols != MaxCols {
		t.Fatalf("state resize not clamped")
	}
}

func TestDeviceReports(t *testing.T) {
	tr := newT(10, 10)
	tr.Feed([]byte("\x1b[3;4H\x1b[6n"))
	if got := string(tr.DrainResponses()); got != "\x1b[3;4R" {
		t.Fatalf("CPR = %q", got)
	}
	tr.Feed([]byte("\x1b[5n"))
	if got := string(tr.DrainResponses()); got != "\x1b[0n" {
		t.Fatalf("DSR = %q", got)
	}
	tr.Feed([]byte("\x1b[c"))
	if !strings.HasPrefix(string(tr.DrainResponses()), "\x1b[?") {
		t.Fatalf("no DA reply")
	}
}

func TestMalformedSequencesDoNotStall(t *testing.T) {
	tr := newT(10, 2)
	// A parameter byte terminates the CSI, so the stream must simply resume.
	tr.Feed([]byte("\x1b[9999999ab"))
	tr.Feed([]byte("\x1b[2J\x1b[H"))
	tr.Feed([]byte("ok"))
	if tr.Screen().RowString(0) != "ok" {
		t.Fatalf("after malformed CSI: %q", dumpRows(tr))
	}
	tr.Feed([]byte("\x1b\x1bM abc"))
	if !strings.Contains(tr.Screen().RowString(0), "abc") {
		t.Fatalf("after stray ESC: %q", tr.Screen().RowString(0))
	}
	tr.Feed([]byte("\x1bP dcs data \x1b\\done"))
	if !strings.Contains(tr.Screen().RowString(0), "done") {
		t.Fatalf("after DCS: %q", tr.Screen().RowString(0))
	}
}

// TestDiffRoundTrip is the property SSP correctness depends on: the byte
// sequence that turns screen A into screen B, replayed into a copy of A, must
// reproduce B exactly, including the cursor.
func TestDiffRoundTrip(t *testing.T) {
	tr := NewTerminalState(40, 8)
	rng := rand.New(rand.NewSource(20261114))
	samples := [][]byte{
		[]byte("hello\r\nworld"),
		[]byte("\x1b[2J\x1b[H"),
		[]byte("\x1b[1;31mRED\x1b[0m normal \x1b[7mREV\x1b[27m"),
		[]byte("\x1b[10;20H"),
		[]byte("\x1b[3;3H\x1b[1L\x1b[2M"),
		[]byte("\u6f22\u5b57\u30c6\u30ad\u30b9\u30c8"),
		[]byte("\x1b[?1049h\x1b[1;1Halt"),
		[]byte("\x1b[?1049l"),
		[]byte("\x1b[2;4r\x1b[4;1H\r\nscroll"),
		[]byte("\tTabbed\tout"),
		[]byte("\x1b]0;title\x07"),
		[]byte("\x1b[38;5;129m256\x1b[0m"),
		[]byte("\x1b[38;2;10;20;30mtrue\x1b[0m"),
		[]byte("\x1b[38;2;0;0;0mblack\x1b[0m"),
		[]byte("\x1b[48:2:0:0:200mbg\x1b[0m"),
		[]byte("\x1b[0;39;48;2;7;0;0mf"),
		[]byte("\x1b[1;38;5;0;48;2;0;0;1m"),
		[]byte("\x1bM\x1bD"),
		[]byte(strings.Repeat("x", 200)),
	}
	for round := 0; round < 300; round++ {
		var payload []byte
		if rng.Intn(2) == 0 {
			payload = samples[rng.Intn(len(samples))]
		} else {
			n := 1 + rng.Intn(60)
			payload = make([]byte, n)
			for i := range payload {
				payload[i] = byte(rng.Intn(256))
			}
		}
		before := tr.Clone().(*TerminalState)
		tr.Feed(payload)
		diff := tr.DiffFrom(before)
		replayed := before.Clone().(*TerminalState)
		if err := replayed.ApplyString(diff); err != nil {
			t.Fatalf("round %d apply %q: %v", round, payload, err)
		}
		if hs := hostStringForDebug(diff); hs != "" {
			t.Logf("round %d hoststring %q", round, hs)
		}
		if !replayed.Equal(tr) {
			t.Logf("replay trace: %s", traceReplay(before, diff, 9, 3))
			t.Fatalf("round %d: replay of diff after %q does not match\n%s\ndiff bytes: %x\nbefore: %q\nafter:  %q\nbefore row3: %s\nafter row3:  %s\nreplay row3: %s cursor %d,%d",
				round, payload, describeStateDiff(replayed, tr), diff, dumpRows(before.Term), dumpRows(tr.Term),
				rowCells(before.Term.Screen(), 3, 12), rowCells(tr.Term.Screen(), 3, 12),
				rowCells(replayed.Term.Screen(), 3, 12), replayed.Term.x, replayed.Term.y)
		}
		fresh := NewTerminalState(40, 8)
		if err := fresh.ApplyString(tr.InitDiff()); err != nil {
			t.Fatalf("round %d init apply: %v", round, err)
		}
		if !fresh.Term.Screen().Equal(tr.Term.Screen()) {
			t.Fatalf("round %d: init diff mismatch\n got %q\nwant %q", round,
				dumpRows(fresh.Term), dumpRows(tr.Term))
		}
	}
}

func TestStateInterfaceShape(t *testing.T) {
	var s stream.State = NewTerminalState(10, 4)
	if s.Clone() == nil {
		t.Fatal("nil clone")
	}
	if err := s.ApplyString(nil); err != nil {
		t.Fatalf("empty diff: %v", err)
	}
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte('a' + i)
	}
	if err := s.ApplyString(hostMessageWithBytes(b)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := dumpRows(s.Clone().(*TerminalState).Term)
	if got[0] != "abcdefghij" || got[1] != "klmnop" {
		t.Fatalf("after feed: %q", got)
	}
}

// TestRendererOnlyTouchesChangedCells guards the property that makes mosh
// bandwidth-efficient: an unchanged screen must produce no output.
func TestRendererOnlyTouchesChangedCells(t *testing.T) {
	tr := NewTerminalState(20, 4)
	tr.Feed([]byte("line one\r\nline two"))
	snapshot := tr.Clone().(*TerminalState)
	if out := tr.DiffFrom(snapshot); len(out) != 0 {
		// The marshalled empty HostMessage is zero bytes.
		t.Fatalf("unchanged screen produced %d bytes of diff", len(out))
	}
	tr.Feed([]byte("\x1b[1;6HX"))
	out := tr.DiffFrom(snapshot)
	if len(out) == 0 {
		t.Fatalf("changed screen produced no diff")
	}
	if len(out) > 60 {
		t.Fatalf("diff unexpectedly large: %d bytes", len(out))
	}
}
