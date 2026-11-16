// Package wire implements the subset of the Protocol Buffers binary wire
// format that winsh needs.  It is written from the published protobuf
// encoding specification; no third-party protobuf runtime is linked.
//
// Only the two wire types used by the mosh protocol are supported for
// writing (varint and length-delimited), and all five non-group wire types
// are accepted for reading so that messages carrying fields winsh does not
// model can still be parsed safely.
package wire

import (
	"errors"
	"fmt"
)

// Wire types, from the protobuf encoding specification.
const (
	WTVarint      = 0
	WTFixed64     = 1
	WTLengthDelim = 2
	WTStartGroup  = 3
	WTEndGroup    = 4
	WTFixed32     = 5
)

// ErrMalformed reports input that cannot be a valid protobuf encoding.
var ErrMalformed = errors.New("winsh/wire: malformed protobuf message")

// maxFieldsPerMessage bounds parser amplification from a message made of many
// tiny fields. Real mosh messages use only a handful.
const maxFieldsPerMessage = 4096

// Buffer incrementally builds a protobuf message.
type Buffer struct {
	buf []byte
}

// NewBuffer returns an empty Buffer.
func NewBuffer() *Buffer { return &Buffer{} }

// Bytes returns the encoded message.
func (b *Buffer) Bytes() []byte { return b.buf }

// String returns the encoded message as a string.
func (b *Buffer) String() string { return string(b.buf) }

// Reset empties the buffer, retaining capacity.
func (b *Buffer) Reset() { b.buf = b.buf[:0] }

// Tag writes a field tag.
func (b *Buffer) Tag(field, wireType int) {
	b.appendVarint(uint64(field)<<3 | uint64(wireType))
}

func (b *Buffer) appendVarint(v uint64) {
	for v >= 0x80 {
		b.buf = append(b.buf, byte(v)|0x80)
		v >>= 7
	}
	b.buf = append(b.buf, byte(v))
}

// Uint64 writes a varint field.  Presence is the caller's decision: this
// method always emits the tag, matching proto2 "explicitly set" semantics.
func (b *Buffer) Uint64(field int, v uint64) {
	b.Tag(field, WTVarint)
	b.appendVarint(v)
}

// Int32 writes a varint field carrying an int32 value.
func (b *Buffer) Int32(field int, v int32) {
	// Negative int32 values are sign-extended to 64 bits on the wire.
	b.Uint64(field, uint64(int64(v)))
}

// Bool writes a bool field as 0/1.
func (b *Buffer) Bool(field int, v bool) {
	var n uint64
	if v {
		n = 1
	}
	b.Uint64(field, n)
}

// Bytes writes a length-delimited field.  A nil slice encodes as a
// zero-length field, which is what proto2 emits for an explicitly set empty
// bytes field.
func (b *Buffer) AppendBytes(field int, v []byte) {
	b.Tag(field, WTLengthDelim)
	b.appendVarint(uint64(len(v)))
	b.buf = append(b.buf, v...)
}

// AppendString writes a length-delimited string field.
func (b *Buffer) AppendString(field int, v string) {
	b.Tag(field, WTLengthDelim)
	b.appendVarint(uint64(len(v)))
	b.buf = append(b.buf, v...)
}

// Submessage writes a nested message, already encoded.
func (b *Buffer) Submessage(field int, encoded []byte) {
	b.AppendBytes(field, encoded)
}

// Field is one decoded top-level field of a message.
type Field struct {
	Num    int
	Type   int
	Number uint64 // valid for WTVarint, WTFixed32, WTFixed64
	Data   []byte // valid for WTLengthDelim
}

// Message is a parsed top-level message.
type Message struct {
	fields []Field
	raw    []byte
}

// Parse decodes the top-level fields of a message.  Nested messages are
// returned as raw bytes and parsed on demand.
func Parse(data []byte) (*Message, error) {
	m := &Message{raw: data}
	in := data
	for len(in) > 0 {
		if len(m.fields) >= maxFieldsPerMessage {
			return nil, fmt.Errorf("%w: more than %d fields", ErrMalformed, maxFieldsPerMessage)
		}
		tag, n := readVarint(in)
		if n <= 0 {
			return nil, ErrMalformed
		}
		in = in[n:]
		num, wt := int(tag>>3), int(tag&7)
		if num == 0 {
			return nil, fmt.Errorf("%w: field number zero", ErrMalformed)
		}
		f := Field{Num: num, Type: wt}
		switch wt {
		case WTVarint:
			v, n := readVarint(in)
			if n <= 0 {
				return nil, ErrMalformed
			}
			f.Number = v
			in = in[n:]
		case WTFixed64:
			if len(in) < 8 {
				return nil, ErrMalformed
			}
			f.Number = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
				uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56
			in = in[8:]
		case WTFixed32:
			if len(in) < 4 {
				return nil, ErrMalformed
			}
			f.Number = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24
			in = in[4:]
		case WTLengthDelim:
			l, n := readVarint(in)
			if n <= 0 || l > uint64(len(in)-n) {
				return nil, ErrMalformed
			}
			in = in[n:]
			f.Data = in[:l]
			in = in[l:]
		default:
			return nil, fmt.Errorf("%w: unsupported wire type %d", ErrMalformed, wt)
		}
		m.fields = append(m.fields, f)
	}
	return m, nil
}

// Fields returns the decoded fields in input order.
func (m *Message) Fields() []Field { return m.fields }

// Raw returns the original encoded message.
func (m *Message) Raw() []byte { return m.raw }

// Last returns the final occurrence of the given field number, which is the
// value protobuf assigns to a singular field, or nil if absent.
func (m *Message) Last(num int) *Field {
	var found *Field
	for i := range m.fields {
		if m.fields[i].Num == num {
			found = &m.fields[i]
		}
	}
	return found
}

func readVarint(in []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i, c := range in {
		if i >= 10 {
			return 0, 0
		}
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			if i == 9 && c > 1 {
				return 0, 0 // overflow of a 64-bit varint
			}
			return v, i + 1
		}
		shift += 7
	}
	return 0, 0
}
