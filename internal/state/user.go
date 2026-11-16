// Package state holds the two streams that mosh synchronises: the user's
// input events travelling to the server, and (in package vt) the terminal
// travelling to the client.
package state

import (
	"bytes"

	"winsh/internal/ssp"
	"winsh/internal/stream"
)

// UserStream is the append-only log of everything the user has typed (and
// every window resize they have caused) that has not yet been confirmed as
// consumed by the server.  Keeping it as an explicit stream ? rather than
// sending bytes blind ? is what lets mosh replay input after a dropout and
// let the client know exactly which keystrokes still need echoing.
type UserStream struct {
	Events []ssp.UserEvent
}

var _ stream.State = (*UserStream)(nil)

// PushByte appends one keystroke byte.
func (u *UserStream) PushByte(b byte) {
	u.Events = append(u.Events, ssp.UserEvent{Byte: b})
}

// PushBytes appends a run of bytes (a paste).
func (u *UserStream) PushBytes(b []byte) {
	for _, c := range b {
		u.Events = append(u.Events, ssp.UserEvent{Byte: c})
	}
}

// PushResize appends a window-size change.
func (u *UserStream) PushResize(cols, rows int) {
	u.Events = append(u.Events, ssp.UserEvent{IsResize: true, Width: int32(cols), Height: int32(rows)})
}

// Len returns the number of pending events.
func (u *UserStream) Len() int { return len(u.Events) }

// Clone returns an independent copy.
func (u *UserStream) Clone() stream.State {
	c := &UserStream{Events: make([]ssp.UserEvent, len(u.Events))}
	copy(c.Events, u.Events)
	return c
}

// Equal reports whether two streams hold the same events.
func (u *UserStream) Equal(o stream.State) bool {
	other, ok := o.(*UserStream)
	if !ok || len(u.Events) != len(other.Events) {
		return false
	}
	for i := range u.Events {
		if u.Events[i] != other.Events[i] {
			return false
		}
	}
	return true
}

// DiffFrom serialises the events that existing does not already have.  A
// non-prefix relationship returns nil: there is no safe diff, and the
// transport must not guess.
func (u *UserStream) DiffFrom(existing stream.State) []byte {
	e, ok := existing.(*UserStream)
	if !ok {
		return nil
	}
	if !u.hasPrefix(e) {
		return nil
	}
	msg := &ssp.UserMessage{Events: u.Events[len(e.Events):]}
	return msg.Marshal()
}

// InitDiff serialises every event.
func (u *UserStream) InitDiff() []byte {
	return (&ssp.UserMessage{Events: u.Events}).Marshal()
}

// ApplyString appends the events carried by a ClientBuffers.UserMessage.
func (u *UserStream) ApplyString(diff []byte) error {
	msg, err := ssp.ParseUserMessage(diff)
	if err != nil {
		return err
	}
	u.Events = append(u.Events, msg.Events...)
	return nil
}

// Subtract drops a prefix the server already has, which keeps the pending
// window small on a long session.
func (u *UserStream) Subtract(prefix stream.State) {
	e, ok := prefix.(*UserStream)
	if !ok || len(e.Events) == 0 {
		return
	}
	if e.Events[0].IsResize && !u.isSameEvent(0, e.Events[0]) {
		return
	}
	if !u.hasPrefix(e) {
		return
	}
	u.Events = u.Events[len(e.Events):]
}

func (u *UserStream) isSameEvent(i int, want ssp.UserEvent) bool {
	if i < 0 || i >= len(u.Events) {
		return false
	}
	return u.Events[i] == want
}

func (u *UserStream) hasPrefix(e *UserStream) bool {
	if len(e.Events) > len(u.Events) {
		return false
	}
	for i := range e.Events {
		if u.Events[i] != e.Events[i] {
			return false
		}
	}
	return true
}

// Bytes returns the keystroke payload of the stream, ignoring resizes.  The
// prediction engine uses it to echo what the user typed.
func (u *UserStream) Bytes() []byte {
	var out []byte
	for _, e := range u.Events {
		if !e.IsResize {
			out = append(out, e.Byte)
		}
	}
	return out
}

// String renders the stream for diagnostics, escaping control bytes so that
// debug output cannot forge terminal control sequences.
func (u *UserStream) String() string {
	var b bytes.Buffer
	for _, e := range u.Events {
		if e.IsResize {
			b.WriteString("<resize ")
			b.WriteString(itoa(int(e.Width)))
			b.WriteString("x")
			b.WriteString(itoa(int(e.Height)))
			b.WriteString(">")
			continue
		}
		if e.Byte >= 0x20 && e.Byte < 0x7F {
			b.WriteByte(e.Byte)
			continue
		}
		b.WriteString("\\x")
		const hexDigits = "0123456789abcdef"
		b.WriteByte(hexDigits[e.Byte>>4])
		b.WriteByte(hexDigits[e.Byte&0xF])
	}
	return b.String()
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
