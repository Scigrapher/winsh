package textsafe

import (
	"strings"
	"testing"
)

func TestTerminalEscapesControlAndFormatCharacters(t *testing.T) {
	got := Terminal("safe\x1b]52;c;secret\x07\u009d\u202eend", 100)
	for _, bad := range []string{"\x1b", "\x07", "\u009d", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Fatalf("Terminal left %q in %q", bad, got)
		}
	}
	for _, want := range []string{`\x1b`, `\x07`, `\x9d`, `\u{202e}`} {
		if !strings.Contains(got, want) {
			t.Errorf("Terminal output %q does not contain %q", got, want)
		}
	}
}

func TestTerminalPreservesLayoutButLineDoesNot(t *testing.T) {
	if got := Terminal("a\nb\tc", 100); got != "a\nb\tc" {
		t.Fatalf("Terminal layout = %q", got)
	}
	if got := Line("a\nb\tc", 100); got != `a\nb\tc` {
		t.Fatalf("Line layout = %q", got)
	}
}

func TestTerminalCapsOutput(t *testing.T) {
	got := Terminal(strings.Repeat("x", 20), 5)
	if got != "xxxxx..." {
		t.Fatalf("capped output = %q", got)
	}
}
