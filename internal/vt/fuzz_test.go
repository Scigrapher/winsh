package vt

import (
	"strings"
	"testing"
)

func FuzzTerminalSequences(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("plain text\r\n"),
		[]byte("\x1b[31mred\x1b[0m"),
		[]byte("\x1b[2J\x1b[10;20Hhello"),
		[]byte("\x1b]0;title\x07"),
		[]byte("\x1b]52;c;AAAA\x07"),
		[]byte("\x1bPignored\x1b\\"),
		[]byte("\x1b[38;2;10;20;30mtruecolor"),
		[]byte("\x1b[" + strings.Repeat(";", 128) + "m"),
		[]byte("\xc2\x9b31mC1-CSI"),
		[]byte("\xe2\x80\xaeRTL"),
	} {
		f.Add(seed)
	}
	f.Add([]byte{0xff, 0xfe, 0xfd})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32*1024 {
			return
		}
		tr := NewTerminal(80, 24)
		tr.Feed(data)
		_ = tr.DrainResponses()
		trimmed := tr.Clone()
		_, _ = trimmed.Title()
		cols, rows := tr.Geometry()
		if cols <= 256 && rows <= 128 {
			x, y, visible := tr.Cursor()
			_ = RenderFrame(NewScreen(cols, rows), tr.Screen(), x, y, visible, RenderOptions{
				Differential: true,
			})
		}
	})
}
