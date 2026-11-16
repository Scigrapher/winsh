package wire

import (
	"bytes"
	"testing"
)

func TestVarintRoundTrip(t *testing.T) {
	cases := []uint64{0, 1, 127, 128, 300, 16383, 16384, 1 << 32, 1<<64 - 1}
	for _, want := range cases {
		b := NewBuffer()
		b.Uint64(1, want)
		m, err := Parse(b.Bytes())
		if err != nil {
			t.Fatalf("parse %d: %v", want, err)
		}
		f := m.Last(1)
		if f == nil || f.Number != want {
			t.Fatalf("round trip %d gave %v", want, f)
		}
	}
}

func TestKnownEncodings(t *testing.T) {
	b := NewBuffer()
	b.Uint64(1, 150)
	if got := b.Bytes(); !bytes.Equal(got, []byte{0x08, 0x96, 0x01}) {
		t.Fatalf("varint encoding = %x", got)
	}
	b.Reset()
	b.AppendBytes(2, []byte("hi"))
	if got := b.Bytes(); !bytes.Equal(got, []byte{0x12, 0x02, 'h', 'i'}) {
		t.Fatalf("bytes encoding = %x", got)
	}
	b.Reset()
	b.AppendBytes(3, nil)
	if got := b.Bytes(); !bytes.Equal(got, []byte{0x1a, 0x00}) {
		t.Fatalf("empty set bytes = %x, want tag plus zero length", got)
	}
	b.Reset()
	b.Int32(5, -1)
	// A negative int32 is sign-extended to ten bytes on the wire.
	m, err := Parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if f := m.Last(5); f == nil || int32(f.Number) != -1 {
		t.Fatalf("negative int32 = %v", f)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	bad := [][]byte{
		{0x00},             // field number zero
		{0x08},             // truncated varint
		{0x08, 0x80},       // truncated varint
		{0x0a, 0x05, 0x01}, // length longer than input
		{0x0b},             // wire type 3 (group, unsupported)
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x08},
	}
	for i, in := range bad {
		if _, err := Parse(in); err == nil {
			t.Errorf("case %d (%x): expected an error", i, in)
		}
	}
}

func TestParseAcceptsUnknownFields(t *testing.T) {
	// A message carrying a 64-bit and a 32-bit field, both of which winsh
	// ignores, must still parse: forward compatibility matters when the
	// protocol grows.
	in := []byte{0x49, 1, 0, 0, 0, 0, 0, 0, 0, 0x15, 2, 0, 0, 0, 0x08, 7}
	m, err := Parse(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f := m.Last(1); f == nil || f.Number != 7 {
		t.Fatalf("varint field = %v", f)
	}
	if f := m.Last(2); f == nil || f.Number != 2 {
		t.Fatalf("fixed32 field = %v", f)
	}
	if f := m.Last(9); f == nil || f.Number != 1 {
		t.Fatalf("fixed64 field = %v", f)
	}
}

func TestRepeatedLastWinsForSingularFields(t *testing.T) {
	b := NewBuffer()
	b.Uint64(3, 1)
	b.Uint64(3, 2)
	m, err := Parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if f := m.Last(3); f.Number != 2 {
		t.Fatalf("Last = %d, want 2", f.Number)
	}
	if len(m.Fields()) != 2 {
		t.Fatalf("Fields = %d, want 2", len(m.Fields()))
	}
}

func TestOverflowingVarintRejected(t *testing.T) {
	// Eleven bytes with a value that does not fit in uint64.
	in := []byte{0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03}
	if _, err := Parse(in); err == nil {
		t.Fatalf("expected overflow rejection")
	}
}
