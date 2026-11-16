package vt

import (
	"fmt"

	"winsh/internal/ssp"
	"winsh/internal/stream"
)

// TerminalState is the transport-facing view of the emulator: a terminal plus
// the echo-acknowledgment counter that mosh piggybacks on terminal updates so
// the client knows how much of its typed input the server has echoed back.
type TerminalState struct {
	Term    *Terminal
	EchoAck uint64
}

var _ stream.State = (*TerminalState)(nil)

// Screen size limits.  A peer must not be able to make the client allocate
// without bound by claiming an enormous window, so sizes are clamped; the
// limits are far above any real console.
const (
	MaxCols = 512
	MaxRows = 512
)

// NewTerminalState returns a blank terminal state.
func NewTerminalState(cols, rows int) *TerminalState {
	return &TerminalState{Term: NewTerminal(clampCols(cols), clampRows(rows))}
}

func clampCols(v int) int {
	if v < 1 {
		return 1
	}
	if v > MaxCols {
		return MaxCols
	}
	return v
}

func clampRows(v int) int {
	if v < 1 {
		return 1
	}
	if v > MaxRows {
		return MaxRows
	}
	return v
}

// Clone deep-copies the state.
func (s *TerminalState) Clone() stream.State {
	c := *s
	c.Term = s.Term.Clone()
	return &c
}

// Equal reports whether two states would render identically.
func (s *TerminalState) Equal(o stream.State) bool {
	other, ok := o.(*TerminalState)
	if !ok {
		return false
	}
	if s.EchoAck != other.EchoAck {
		return false
	}
	a, b := s.Term, other.Term
	if a.x != b.x || a.y != b.y || a.cursorVisible != b.cursorVisible {
		return false
	}
	return a.Screen().Equal(b.Screen())
}

// ApplyString consumes a HostBuffers.HostMessage diff.
func (s *TerminalState) ApplyString(diff []byte) error {
	hm, err := ssp.ParseHostMessage(diff)
	if err != nil {
		return err
	}
	for _, in := range hm.Instructions {
		switch in.Kind {
		case ssp.HostKindBytes:
			s.Term.Feed(in.Bytes)
		case ssp.HostKindResize:
			if in.Width > 0 && in.Height > 0 {
				s.Term.Resize(clampCols(int(in.Width)), clampRows(int(in.Height)))
			}
		case ssp.HostKindEcho:
			// The counter only moves forward; a backward jump is a protocol
			// violation but harmless to drop.
			if in.EchoAckNum > s.EchoAck {
				s.EchoAck = in.EchoAckNum
			}
		default:
			return fmt.Errorf("vt: unknown host instruction %d", in.Kind)
		}
	}
	return nil
}

// InitDiff renders the whole screen, as if the peer had an empty terminal of
// the same size.
func (s *TerminalState) InitDiff() []byte {
	blank := NewTerminalState(s.Term.cols, s.Term.rows)
	return s.DiffFrom(blank)
}

// DiffFrom produces the HostMessage that replays existing into s.
func (s *TerminalState) DiffFrom(existing stream.State) []byte {
	e, ok := existing.(*TerminalState)
	if !ok {
		return nil
	}
	var hm ssp.HostMessage
	if s.EchoAck != e.EchoAck && s.EchoAck > e.EchoAck {
		hm.Instructions = append(hm.Instructions,
			ssp.HostInstruction{Kind: ssp.HostKindEcho, EchoAckNum: s.EchoAck})
	}
	oldScr, newScr := e.Term.Screen(), s.Term.Screen()
	if oldScr.Equal(newScr) && e.Term.x == s.Term.x && e.Term.y == s.Term.y &&
		e.Term.cursorVisible == s.Term.cursorVisible {
		return hm.Marshal()
	}
	if oldScr.Cols != newScr.Cols || oldScr.Rows != newScr.Rows {
		hm.Instructions = append(hm.Instructions, ssp.HostInstruction{
			Kind: ssp.HostKindResize, Width: int32(newScr.Cols), Height: int32(newScr.Rows)})
	}
	out := RenderFrame(oldScr, newScr, s.Term.x, s.Term.y, s.Term.cursorVisible, RenderOptions{
		Differential: !DiffFull,
	})
	if len(out) > 0 {
		hm.Instructions = append(hm.Instructions, ssp.HostInstruction{Kind: ssp.HostKindBytes, Bytes: out})
	}
	return hm.Marshal()
}

// Subtract is a no-op: a terminal state is not an append-only stream.
func (s *TerminalState) Subtract(stream.State) {}

// Feed is a convenience for tests and for the built-in test server.
func (s *TerminalState) Feed(b []byte) { s.Term.Feed(b) }
