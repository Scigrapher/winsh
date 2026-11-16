// Package textsafe prepares untrusted text for display on a terminal.
package textsafe

import (
	"fmt"
	"strings"
	"unicode"
)

// Terminal returns s with terminal control characters and Unicode format
// characters escaped. Newlines and tabs are preserved. At most maxRunes
// printable runes are returned.
func Terminal(s string, maxRunes int) string {
	return sanitize(s, maxRunes, true)
}

// Line is Terminal with newlines and tabs escaped as well, for contexts where
// the caller needs exactly one displayed line.
func Line(s string, maxRunes int) string {
	return sanitize(s, maxRunes, false)
}

func sanitize(s string, maxRunes int, allowLayout bool) string {
	if maxRunes <= 0 {
		maxRunes = 4096
	}
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if n >= maxRunes {
			b.WriteString("...")
			break
		}
		switch {
		case r == '\n' && allowLayout:
			b.WriteByte('\n')
		case r == '\t' && allowLayout:
			b.WriteByte('\t')
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r):
			writeEscapedRune(&b, r)
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

func writeEscapedRune(b *strings.Builder, r rune) {
	if r <= 0xff {
		fmt.Fprintf(b, `\x%02x`, r)
		return
	}
	fmt.Fprintf(b, `\u{%x}`, r)
}
