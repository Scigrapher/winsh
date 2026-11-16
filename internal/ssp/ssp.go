// Package ssp encodes and decodes the messages exchanged by the mosh State
// Synchronization Protocol (SSP) and its two terminal "buffers" protocols.
//
// The message shapes are dictated by the wire interface that mosh servers
// speak; they are re-implemented here from the published interface.  See
// internal/licenses for the attribution notes.
package ssp

import (
	"errors"
	"fmt"

	"winsh/internal/wire"
)

// ProtocolVersion is the value mosh servers require in
// TransportBuffers.Instruction.protocol_version.  Version 2 is the version
// that added the echo-ack instruction.
const ProtocolVersion = 2

// Instruction is TransportBuffers.Instruction, the single message that
// carries all SSP state updates in both directions.
type Instruction struct {
	ProtocolVersion uint64
	HasProtocol     bool
	OldNum          uint64
	HasOldNum       bool
	NewNum          uint64
	HasNewNum       bool
	AckNum          uint64
	HasAckNum       bool
	ThrowawayNum    uint64
	HasThrowaway    bool
	Diff            []byte
	HasDiff         bool
	Chaff           []byte
	HasChaff        bool
}

// Marshal encodes the instruction, emitting only the fields that have been
// explicitly set (proto2 optional semantics).
func (in *Instruction) Marshal() []byte {
	b := wire.NewBuffer()
	if in.HasProtocol {
		b.Uint64(1, in.ProtocolVersion)
	}
	if in.HasOldNum {
		b.Uint64(2, in.OldNum)
	}
	if in.HasNewNum {
		b.Uint64(3, in.NewNum)
	}
	if in.HasAckNum {
		b.Uint64(4, in.AckNum)
	}
	if in.HasThrowaway {
		b.Uint64(5, in.ThrowawayNum)
	}
	if in.HasDiff {
		b.AppendBytes(6, in.Diff)
	}
	if in.HasChaff {
		b.AppendBytes(7, in.Chaff)
	}
	return b.Bytes()
}

// ParseInstruction decodes a TransportBuffers.Instruction.
func ParseInstruction(data []byte) (*Instruction, error) {
	m, err := wire.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("instruction: %w", err)
	}
	out := &Instruction{}
	for _, f := range m.Fields() {
		switch f.Num {
		case 1:
			if f.Type != wire.WTVarint {
				return nil, errors.New("instruction: bad protocol_version")
			}
			out.ProtocolVersion, out.HasProtocol = f.Number, true
		case 2:
			if f.Type != wire.WTVarint {
				return nil, errors.New("instruction: bad old_num")
			}
			out.OldNum, out.HasOldNum = f.Number, true
		case 3:
			if f.Type != wire.WTVarint {
				return nil, errors.New("instruction: bad new_num")
			}
			out.NewNum, out.HasNewNum = f.Number, true
		case 4:
			if f.Type != wire.WTVarint {
				return nil, errors.New("instruction: bad ack_num")
			}
			out.AckNum, out.HasAckNum = f.Number, true
		case 5:
			if f.Type != wire.WTVarint {
				return nil, errors.New("instruction: bad throwaway_num")
			}
			out.ThrowawayNum, out.HasThrowaway = f.Number, true
		case 6:
			if f.Type != wire.WTLengthDelim {
				return nil, errors.New("instruction: bad diff")
			}
			out.Diff, out.HasDiff = f.Data, true
		case 7:
			if f.Type != wire.WTLengthDelim {
				return nil, errors.New("instruction: bad chaff")
			}
			out.Chaff, out.HasChaff = f.Data, true
		}
	}
	return out, nil
}

// UserEvent is one client-to-server state change: a keystroke byte or a
// window resize.
type UserEvent struct {
	Byte          byte
	IsResize      bool
	Width, Height int32
}

// UserMessage is ClientBuffers.UserMessage: the diff of the client's input
// stream.  Keystrokes run together into a single instruction, exactly as the
// reference implementation does, because that is what keeps diffs short.
type UserMessage struct {
	Events []UserEvent
}

// Marshal encodes the message.
func (um *UserMessage) Marshal() []byte {
	b := wire.NewBuffer()
	for i := 0; i < len(um.Events); {
		ev := um.Events[i]
		if ev.IsResize {
			sub := wire.NewBuffer()
			sub.Int32(5, ev.Width)
			sub.Int32(6, ev.Height)
			outer := wire.NewBuffer()
			outer.AppendBytes(3, sub.Bytes())
			b.AppendBytes(1, outer.Bytes())
			i++
			continue
		}
		// Coalesce a run of keystrokes into one Keystroke instruction.
		start := i
		for i < len(um.Events) && !um.Events[i].IsResize {
			i++
		}
		keys := make([]byte, 0, i-start)
		for _, e := range um.Events[start:i] {
			keys = append(keys, e.Byte)
		}
		inner := wire.NewBuffer()
		inner.AppendBytes(4, keys)
		outer := wire.NewBuffer()
		outer.AppendBytes(2, inner.Bytes())
		b.AppendBytes(1, outer.Bytes())
	}
	return b.Bytes()
}

// ParseUserMessage decodes a ClientBuffers.UserMessage.  It is used by
// winsh's built-in test server and by the unit tests.
func ParseUserMessage(data []byte) (*UserMessage, error) {
	m, err := wire.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("user message: %w", err)
	}
	out := &UserMessage{}
	for _, f := range m.Fields() {
		if f.Num != 1 || f.Type != wire.WTLengthDelim {
			continue
		}
		im, err := wire.Parse(f.Data)
		if err != nil {
			return nil, fmt.Errorf("user instruction: %w", err)
		}
		for _, sub := range im.Fields() {
			switch sub.Num {
			case 2: // keystroke
				km, err := wire.Parse(sub.Data)
				if err != nil {
					return nil, fmt.Errorf("keystroke: %w", err)
				}
				kf := km.Last(4)
				if kf == nil || kf.Type != wire.WTLengthDelim {
					continue
				}
				for _, c := range kf.Data {
					out.Events = append(out.Events, UserEvent{Byte: c})
				}
			case 3: // resize
				rm, err := wire.Parse(sub.Data)
				if err != nil {
					return nil, fmt.Errorf("resize: %w", err)
				}
				var w, h int32
				if x := rm.Last(5); x != nil {
					w = int32(x.Number)
				}
				if x := rm.Last(6); x != nil {
					h = int32(x.Number)
				}
				out.Events = append(out.Events, UserEvent{IsResize: true, Width: w, Height: h})
			}
		}
	}
	return out, nil
}

// Host instruction kinds carried inside HostBuffers.HostMessage.
const (
	HostKindBytes  = 1 // terminal output for the client emulator
	HostKindResize = 2 // server-side window size
	HostKindEcho   = 3 // acknowledgment of echoed input
)

// HostInstruction is one entry of HostBuffers.HostMessage.
type HostInstruction struct {
	Kind       int
	Bytes      []byte // HostKindBytes
	Width      int32  // HostKindResize
	Height     int32
	EchoAckNum uint64 // HostKindEcho
}

// HostMessage is HostBuffers.HostMessage: the diff of the server's terminal
// state, expressed as terminal octets plus a couple of out-of-band hints.
type HostMessage struct {
	Instructions []HostInstruction
}

// Marshal encodes the message.
func (hm *HostMessage) Marshal() []byte {
	b := wire.NewBuffer()
	for _, in := range hm.Instructions {
		outer := wire.NewBuffer()
		switch in.Kind {
		case HostKindBytes:
			inner := wire.NewBuffer()
			inner.AppendBytes(4, in.Bytes)
			outer.AppendBytes(2, inner.Bytes())
		case HostKindResize:
			inner := wire.NewBuffer()
			inner.Int32(5, in.Width)
			inner.Int32(6, in.Height)
			outer.AppendBytes(3, inner.Bytes())
		case HostKindEcho:
			inner := wire.NewBuffer()
			inner.Uint64(8, in.EchoAckNum)
			outer.AppendBytes(7, inner.Bytes())
		default:
			continue
		}
		b.AppendBytes(1, outer.Bytes())
	}
	return b.Bytes()
}

// ParseHostMessage decodes a HostBuffers.HostMessage.
func ParseHostMessage(data []byte) (*HostMessage, error) {
	m, err := wire.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("host message: %w", err)
	}
	out := &HostMessage{}
	for _, f := range m.Fields() {
		if f.Num != 1 || f.Type != wire.WTLengthDelim {
			continue
		}
		im, err := wire.Parse(f.Data)
		if err != nil {
			return nil, fmt.Errorf("host instruction: %w", err)
		}
		for _, sub := range im.Fields() {
			if sub.Type != wire.WTLengthDelim {
				continue
			}
			switch sub.Num {
			case 2: // hostbytes
				hm, err := wire.Parse(sub.Data)
				if err != nil {
					return nil, fmt.Errorf("hostbytes: %w", err)
				}
				if hf := hm.Last(4); hf != nil && hf.Type == wire.WTLengthDelim {
					out.Instructions = append(out.Instructions,
						HostInstruction{Kind: HostKindBytes, Bytes: hf.Data})
				}
			case 3: // resize
				rm, err := wire.Parse(sub.Data)
				if err != nil {
					return nil, fmt.Errorf("host resize: %w", err)
				}
				var w, h int32
				if x := rm.Last(5); x != nil {
					w = int32(x.Number)
				}
				if x := rm.Last(6); x != nil {
					h = int32(x.Number)
				}
				out.Instructions = append(out.Instructions,
					HostInstruction{Kind: HostKindResize, Width: w, Height: h})
			case 7: // echoack
				em, err := wire.Parse(sub.Data)
				if err != nil {
					return nil, fmt.Errorf("echoack: %w", err)
				}
				if x := em.Last(8); x != nil {
					out.Instructions = append(out.Instructions,
						HostInstruction{Kind: HostKindEcho, EchoAckNum: x.Number})
				}
			}
		}
	}
	return out, nil
}
