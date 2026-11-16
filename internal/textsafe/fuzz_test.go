package textsafe

import (
	"strings"
	"testing"
	"unicode"
)

func FuzzTerminalText(f *testing.F) {
	f.Add("plain text")
	f.Add("line one\nline two\tend")
	f.Add("bad\x1b]52;c;secret\x07")
	f.Add("c1 \u009d and bidi \u202e")
	f.Add(strings.Repeat("x", 5000))
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64*1024 {
			return
		}
		terminal := Terminal(input, 256)
		line := Line(input, 256)
		if len(terminal) > 10*256+3 || len(line) > 10*256+3 {
			t.Fatalf("sanitized output exceeded its bound: terminal=%d line=%d", len(terminal), len(line))
		}
		for _, r := range terminal {
			if r != '\n' && r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r)) {
				t.Fatalf("Terminal left control or format rune %U", r)
			}
		}
		for _, r := range line {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("Line left control or format rune %U", r)
			}
		}
	})
}
