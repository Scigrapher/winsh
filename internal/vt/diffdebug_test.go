package vt

import (
	"fmt"

	"winsh/internal/ssp"
)

// describeStateDiff reports the first concrete difference between two terminal
// states, which turns a round-trip failure into something diagnosable.
func describeStateDiff(a, b *TerminalState) string {
	if a.EchoAck != b.EchoAck {
		return fmt.Sprintf("echoack %d vs %d", a.EchoAck, b.EchoAck)
	}
	if a.Term.x != b.Term.x || a.Term.y != b.Term.y {
		return fmt.Sprintf("cursor %d,%d vs %d,%d", a.Term.x, a.Term.y, b.Term.x, b.Term.y)
	}
	if a.Term.cursorVisible != b.Term.cursorVisible {
		return fmt.Sprintf("cursor visible %v vs %v", a.Term.cursorVisible, b.Term.cursorVisible)
	}
	sa, sb := a.Term.Screen(), b.Term.Screen()
	if sa.Cols != sb.Cols || sa.Rows != sb.Rows {
		return fmt.Sprintf("geometry %dx%d vs %dx%d", sa.Cols, sa.Rows, sb.Cols, sb.Rows)
	}
	for y := 0; y < sa.Rows; y++ {
		for x := 0; x < sa.Cols; x++ {
			ca, cb := sa.At(x, y), sb.At(x, y)
			if !ca.Equal(cb) {
				return fmt.Sprintf("cell (%d,%d): %+v vs %+v\nrows a: %q\nrows b: %q",
					x, y, ca, cb, dumpRows(a.Term), dumpRows(b.Term))
			}
		}
	}
	return "states compare equal (equality check is wrong)"
}

// traceReplay applies a diff one byte at a time and reports the byte index at
// which a chosen cell first differs from the target, plus the parser state.
func traceReplay(before *TerminalState, diff []byte, x, y int) string {
	hm, err := ssp.ParseHostMessage(diff)
	if err != nil {
		return "cannot parse diff: " + err.Error()
	}
	var data []byte
	for _, in := range hm.Instructions {
		if in.Kind == ssp.HostKindBytes {
			data = append(data, in.Bytes...)
		}
	}
	st := before.Clone().(*TerminalState)
	for i := 0; i < len(data); i++ {
		st.Term.Feed(data[i : i+1])
		c := st.Term.Screen().At(x, y)
		if c.Raw != 0x20 {
			return fmt.Sprintf("byte %d (%q) made cell (%d,%d) = %q; parser state=%d utf8Seen=%d context=%q",
				i, data[i], x, y, string(c.Raw), st.Term.ps.state, st.Term.ps.utf8Seen, string(max(data[:i], 20)))
		}
	}
	return "cell stayed blank through the whole diff"
}

func max(a []byte, n int) []byte {
	if len(a) > n {
		return a[len(a)-n:]
	}
	return a
}
