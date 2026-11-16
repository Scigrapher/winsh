package predict

import (
	"strings"
	"testing"
	"time"

	"winsh/internal/vt"
)

func terminalWith(t *testing.T, cols, rows int, text string) *vt.Terminal {
	t.Helper()
	term := vt.NewTerminal(cols, rows)
	term.Feed([]byte(text))
	return term
}

func rowText(term *vt.Terminal, y int) string {
	return term.Screen().RowString(y)
}

func TestAlwaysShowsPredictionImmediately(t *testing.T) {
	e := New(Options{Mode: ModeAlways})
	base := terminalWith(t, 20, 3, "")
	now := time.Now()

	e.AddInput([]byte("typing"), base, 1, now)
	got := e.Render(base)
	if text := rowText(got, 0); text != "typing" {
		t.Fatalf("predicted row = %q, want typing", text)
	}
	if x, y, visible := got.Cursor(); x != 6 || y != 0 || !visible {
		t.Fatalf("cursor = (%d,%d,%v), want (6,0,true)", x, y, visible)
	}
}

func TestInsertAndOverwritePrediction(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		overwrite bool
		want      string
	}{
		{"insert", false, "abXcd"},
		{"overwrite", true, "abXd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := terminalWith(t, 20, 3, "abcd")
			base.SetCursor(2, 0)
			e := New(Options{Mode: ModeAlways, Overwrite: tc.overwrite})
			e.AddInput([]byte("X"), base, 1, now)
			if text := rowText(e.Render(base), 0); text != tc.want {
				t.Fatalf("row = %q, want %q", text, tc.want)
			}
		})
	}
}

func TestMidWordCorrectionAndBackspace(t *testing.T) {
	now := time.Now()

	base := terminalWith(t, 20, 3, "helo")
	base.SetCursor(3, 0)
	e := New(Options{Mode: ModeAlways})
	e.AddInput([]byte("l"), base, 1, now)
	if text := rowText(e.Render(base), 0); text != "hello" {
		t.Fatalf("mid-word insert = %q, want hello", text)
	}

	base = terminalWith(t, 20, 3, "abcd")
	base.SetCursor(4, 0)
	e = New(Options{Mode: ModeAlways})
	e.AddInput([]byte("x\x7f"), base, 1, now)
	if text := rowText(e.Render(base), 0); text != "abcd" {
		t.Fatalf("type then backspace = %q, want abcd", text)
	}
}

func TestArrowCursorPrediction(t *testing.T) {
	base := terminalWith(t, 20, 3, "ac")
	base.SetCursor(2, 0)
	e := New(Options{Mode: ModeAlways})
	e.AddInput([]byte("\x1b[Db"), base, 1, time.Now())
	if text := rowText(e.Render(base), 0); text != "abc" {
		t.Fatalf("left-arrow insert = %q, want abc", text)
	}
}

func TestEchoAckRetiresPredictionWithoutDuplication(t *testing.T) {
	now := time.Now()
	e := New(Options{Mode: ModeAlways})
	base := terminalWith(t, 20, 3, "")
	e.AddInput([]byte("hello"), base, 4, now)

	// The server has now echoed the input in a later authoritative state.
	echoed := terminalWith(t, 20, 3, "hello")
	e.Observe(echoed, 4, 4, 20*time.Millisecond, now.Add(20*time.Millisecond))
	got := e.Render(echoed)
	if text := rowText(got, 0); text != "hello" {
		t.Fatalf("row after confirmation = %q, want one hello", text)
	}
	if e.Pending() {
		t.Fatal("prediction remained pending after matching echo ack")
	}
}

func TestMismatchDiscardsSpeculation(t *testing.T) {
	now := time.Now()
	e := New(Options{Mode: ModeAlways})
	base := terminalWith(t, 20, 3, "")
	e.AddInput([]byte("abc"), base, 2, now)

	// The remote program transformed the input.  The authoritative state must
	// replace the prediction, rather than leaving "abc" on screen forever.
	actual := terminalWith(t, 20, 3, "axc")
	e.Observe(actual, 2, 2, 20*time.Millisecond, now.Add(20*time.Millisecond))
	if text := rowText(e.Render(actual), 0); text != "axc" {
		t.Fatalf("row after mismatch = %q, want axc", text)
	}
}

func TestPredictionWaitsOutEchoWindowBeforeCancelling(t *testing.T) {
	now := time.Now()
	e := New(Options{Mode: ModeAlways})
	base := terminalWith(t, 20, 3, "")
	e.AddInput([]byte("secret"), base, 3, now)

	// SSP received the input, but no echo has arrived yet.  Do not interpret
	// that immediately as a non-echoing prompt.
	e.Observe(base, 0, 3, 20*time.Millisecond, now.Add(10*time.Millisecond))
	if text := rowText(e.Render(base), 0); text != "secret" {
		t.Fatalf("prediction vanished before the echo window: %q", text)
	}

	// The window expired and the authoritative screen is still blank: this is
	// a password-style prompt, so the speculative text must disappear.
	e.Observe(base, 0, 3, 20*time.Millisecond, now.Add(150*time.Millisecond))
	if text := rowText(e.Render(base), 0); text != "" {
		t.Fatalf("non-echoing prediction survived: %q", text)
	}
}

func TestAdaptiveWaitsForConfidence(t *testing.T) {
	now := time.Now()
	e := New(Options{Mode: ModeAdaptive})
	base := terminalWith(t, 20, 3, "")
	e.Observe(base, 0, 0, 10*time.Millisecond, now)

	e.AddInput([]byte("a"), base, 1, now)
	if text := rowText(e.Render(base), 0); text != "" {
		t.Fatalf("unconfirmed first prediction = %q, want hidden", text)
	}

	echoed := terminalWith(t, 20, 3, "a")
	e.Observe(echoed, 0, 1, 10*time.Millisecond, now.Add(20*time.Millisecond))
	e.AddInput([]byte("b"), echoed, 2, now.Add(20*time.Millisecond))
	if text := rowText(e.Render(echoed), 0); text != "ab" {
		t.Fatalf("prediction after confidence = %q, want ab", text)
	}
}

func TestSlowLinkUnderlinesOutstandingPrediction(t *testing.T) {
	now := time.Now()
	e := New(Options{Mode: ModeAdaptive})
	base := terminalWith(t, 20, 3, "")
	e.Observe(base, 0, 0, 120*time.Millisecond, now)
	e.AddInput([]byte("x"), base, 1, now)
	got := e.Render(base)
	cell := got.Screen().At(0, 0)
	if cell.Raw != 'x' || cell.Attr&vt.AttrUnderline == 0 {
		t.Fatalf("outstanding cell = %+v, want underlined x", cell)
	}
}

func TestWideGlyphIsLeftToServer(t *testing.T) {
	e := New(Options{Mode: ModeAlways})
	base := terminalWith(t, 20, 3, "")
	e.AddInput([]byte("界"), base, 1, time.Now())
	if text := rowText(e.Render(base), 0); strings.TrimSpace(text) != "" {
		t.Fatalf("wide glyph was guessed: %q", text)
	}
}

func TestRenderDoesNotMutateAuthoritativeScreen(t *testing.T) {
	e := New(Options{Mode: ModeAlways})
	base := terminalWith(t, 20, 3, "base")
	base.SetCursor(4, 0)
	e.AddInput([]byte("+prediction"), base, 1, time.Now())
	_ = e.Render(base)
	if text := rowText(base, 0); text != "base" {
		t.Fatalf("authoritative screen changed to %q", text)
	}
}
