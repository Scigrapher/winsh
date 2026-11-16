package ssp

import (
	"bytes"
	"testing"
)

func TestInstructionRoundTrip(t *testing.T) {
	in := &Instruction{
		ProtocolVersion: ProtocolVersion, HasProtocol: true,
		OldNum: 5, HasOldNum: true, NewNum: 9, HasNewNum: true,
		AckNum: 3, HasAckNum: true, ThrowawayNum: 1, HasThrowaway: true,
		Diff: []byte{0, 1, 2, 255}, HasDiff: true,
		Chaff: []byte("chaff"), HasChaff: true,
	}
	out, err := ParseInstruction(in.Marshal())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.ProtocolVersion != in.ProtocolVersion || out.OldNum != in.OldNum ||
		out.NewNum != in.NewNum || out.AckNum != in.AckNum || out.ThrowawayNum != in.ThrowawayNum ||
		!bytes.Equal(out.Diff, in.Diff) || !bytes.Equal(out.Chaff, in.Chaff) ||
		!out.HasProtocol || !out.HasOldNum || !out.HasNewNum || !out.HasAckNum ||
		!out.HasThrowaway || !out.HasDiff || !out.HasChaff {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestInstructionPresence(t *testing.T) {
	// An explicitly set empty diff still appears on the wire (proto2 "set"
	// semantics), and an unset field does not.
	e := &Instruction{HasDiff: true, Diff: nil}
	m, err := ParseInstruction(e.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasDiff || len(m.Diff) != 0 {
		t.Fatalf("empty set diff lost: %+v", m)
	}
	if m.HasNewNum || m.HasOldNum || m.HasChaff {
		t.Fatalf("unset fields appeared: %+v", m)
	}
}

func TestKeystrokeMessageExactBytes(t *testing.T) {
	um := &UserMessage{Events: []UserEvent{{Byte: 'h'}, {Byte: 'i'}}}
	got := um.Marshal()
	// UserMessage{ instruction{ [keystroke=2]{ [keys=4]="hi" } } }
	want := []byte{0x0a, 0x06, 0x12, 0x04, 0x22, 0x02, 'h', 'i'}
	if !bytes.Equal(got, want) {
		t.Fatalf("keystroke encoding = %x, want %x", got, want)
	}
	back, err := ParseUserMessage(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(back.Events) != 2 || back.Events[0].Byte != 'h' || back.Events[1].Byte != 'i' {
		t.Fatalf("round trip = %+v", back.Events)
	}
}

func TestUserMessageMixedEvents(t *testing.T) {
	um := &UserMessage{Events: []UserEvent{
		{Byte: 'a'}, {Byte: 'b'},
		{IsResize: true, Width: 132, Height: 43},
		{Byte: 'c'},
	}}
	back, err := ParseUserMessage(um.Marshal())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(back.Events) != 4 {
		t.Fatalf("events = %+v", back.Events)
	}
	if !back.Events[2].IsResize || back.Events[2].Width != 132 || back.Events[2].Height != 43 {
		t.Fatalf("resize lost: %+v", back.Events[2])
	}
	if back.Events[3].Byte != 'c' {
		t.Fatalf("trailing keystroke lost: %+v", back.Events[3])
	}
}

func TestHostMessageRoundTrip(t *testing.T) {
	hm := &HostMessage{Instructions: []HostInstruction{
		{Kind: HostKindResize, Width: 80, Height: 24},
		{Kind: HostKindBytes, Bytes: []byte("\x1b[2Jhello")},
		{Kind: HostKindEcho, EchoAckNum: 1234567890123},
	}}
	back, err := ParseHostMessage(hm.Marshal())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(back.Instructions) != 3 {
		t.Fatalf("instructions = %+v", back.Instructions)
	}
	if back.Instructions[0].Width != 80 || back.Instructions[0].Height != 24 {
		t.Fatalf("resize = %+v", back.Instructions[0])
	}
	if string(back.Instructions[1].Bytes) != "\x1b[2Jhello" {
		t.Fatalf("hostbytes = %q", back.Instructions[1].Bytes)
	}
	if back.Instructions[2].EchoAckNum != 1234567890123 {
		t.Fatalf("echoack = %+v", back.Instructions[2])
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	if _, err := ParseInstruction([]byte{0x06, 0xff}); err == nil {
		t.Fatalf("expected error for truncated diff")
	}
	if _, err := ParseHostMessage([]byte{0x0a, 0x7f, 0x12}); err == nil {
		t.Fatalf("expected error for truncated instruction")
	}
	if _, err := ParseUserMessage([]byte{0xff, 0xff}); err == nil {
		t.Fatalf("expected error for garbage")
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	// A future server might add field 8 to Instruction; it must not break us.
	raw := append((&Instruction{NewNum: 4, HasNewNum: true}).Marshal(), 0x40, 0x01)
	in, err := ParseInstruction(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !in.HasNewNum || in.NewNum != 4 {
		t.Fatalf("lost new_num with unknown field present: %+v", in)
	}
}
