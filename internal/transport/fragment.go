package transport

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"winsh/internal/ssp"
)

// Fragmentation and compression of Instructions.
//
// mosh compresses each Instruction with zlib (RFC 1950, the "zlib" wrapper
// format, at the default level) and then splits the result into datagram-sized
// fragments carrying a 64-bit instruction id and a 15-bit fragment number with
// a "final" flag in the top bit.  winsh uses Go's standard-library zlib for
// the compression, so no third-party deflate code is involved.

// Limits chosen to bound memory use against a hostile peer.
const (
	// MaxInflatedBytes is the same effective cap the reference implementation
	// puts on an uncompressed Instruction (2048*2048).
	MaxInflatedBytes = 2048 * 2048
	// MaxFragments bounds how many fragments may make up one instruction.
	// 1024 fragments at the transport MTU is far more than a legitimate
	// terminal update ever needs.
	MaxFragments = 1024
	// MaxFragmentContents bounds a single fragment's payload.
	MaxFragmentContents = 4096
)

// Fragment is one datagram-sized piece of a compressed Instruction.
type Fragment struct {
	ID       uint64
	Num      uint16
	Final    bool
	Contents []byte
}

// ParseFragment decodes a fragment from a decrypted packet payload.
func ParseFragment(b []byte) (*Fragment, error) {
	if len(b) < FragmentHeaderBytes {
		return nil, fmt.Errorf("%w: fragment too short", ErrProtocol)
	}
	f := &Fragment{}
	f.ID = binary.BigEndian.Uint64(b[0:8])
	combined := binary.BigEndian.Uint16(b[8:10])
	f.Final = combined&0x8000 != 0
	f.Num = combined & 0x7fff
	f.Contents = b[FragmentHeaderBytes:]
	if len(f.Contents) > MaxFragmentContents {
		return nil, fmt.Errorf("%w: oversized fragment", ErrProtocol)
	}
	return f, nil
}

// Marshal encodes the fragment as a packet payload.
func (f *Fragment) Marshal() []byte {
	out := make([]byte, FragmentHeaderBytes+len(f.Contents))
	binary.BigEndian.PutUint64(out[0:8], f.ID)
	combined := f.Num & 0x7fff
	if f.Final {
		combined |= 0x8000
	}
	binary.BigEndian.PutUint16(out[8:10], combined)
	copy(out[FragmentHeaderBytes:], f.Contents)
	return out
}

// Assembly reassembles fragments that share an instruction id.
type Assembly struct {
	currentID     uint64
	haveID        bool
	fragments     []*Fragment
	arrived       int
	total         int
	bytesReceived int
}

// Add records a fragment and reports whether the instruction is complete.
// A duplicate fragment with different contents is a protocol violation: it
// would let a peer make the client render two different states under one
// sequence number.
func (a *Assembly) Add(f *Fragment) (bool, error) {
	if f.Num >= MaxFragments {
		return false, fmt.Errorf("%w: fragment number %d too large", ErrProtocol, f.Num)
	}
	if !a.haveID || a.currentID != f.ID {
		a.fragments = make([]*Fragment, 0, 8)
		a.arrived = 0
		a.total = -1
		a.currentID = f.ID
		a.haveID = true
		a.bytesReceived = 0
	}
	for int(len(a.fragments)) <= int(f.Num) {
		a.fragments = append(a.fragments, nil)
	}
	if a.fragments[f.Num] != nil {
		if !bytes.Equal(a.fragments[f.Num].Contents, f.Contents) {
			return false, fmt.Errorf("%w: conflicting retransmission of fragment %d", ErrProtocol, f.Num)
		}
		return a.arrived == a.total && a.total > 0, nil
	}
	a.fragments[f.Num] = f
	a.arrived++
	a.bytesReceived += len(f.Contents)
	if a.bytesReceived > MaxFragments*MaxFragmentContents {
		a.reset()
		return false, fmt.Errorf("%w: instruction too large", ErrProtocol)
	}
	if f.Final {
		if int(f.Num)+1 > MaxFragments {
			a.reset()
			return false, fmt.Errorf("%w: too many fragments", ErrProtocol)
		}
		a.total = int(f.Num) + 1
		for len(a.fragments) < a.total {
			a.fragments = append(a.fragments, nil)
		}
	}
	return a.total > 0 && a.arrived == a.total, nil
}

func (a *Assembly) reset() {
	a.fragments = nil
	a.arrived = 0
	a.total = -1
	a.haveID = false
	a.bytesReceived = 0
}

// Instruction decodes the completed instruction and forgets it, so that a
// retransmission is treated as a fresh (identical) instruction.
func (a *Assembly) Instruction() (*ssp.Instruction, error) {
	if a.total <= 0 || a.arrived != a.total {
		return nil, errors.New("transport: instruction not complete")
	}
	buf := make([]byte, 0, a.bytesReceived)
	for _, f := range a.fragments {
		if f == nil {
			return nil, fmt.Errorf("%w: missing fragment", ErrProtocol)
		}
		buf = append(buf, f.Contents...)
	}
	a.reset()
	raw, err := Inflate(buf, MaxInflatedBytes)
	if err != nil {
		return nil, err
	}
	inst, err := ssp.ParseInstruction(raw)
	if err != nil {
		return nil, err
	}
	// ParseInstruction slices Diff out of the inflated buffer.  Retaining that
	// slice would pin the whole decompressed instruction (up to
	// MaxInflatedBytes) for every state in the receiver's window, even when
	// the diff itself is only a few hundred bytes.  Copy it to an exact-sized
	// allocation so the inflated buffer can be collected.
	if inst.HasDiff {
		inst.Diff = append([]byte(nil), inst.Diff...)
	}
	return inst, nil
}

// Compress deflates b using the zlib wrapper format.
func Compress(b []byte) ([]byte, error) {
	var out bytes.Buffer
	// Level 6 is zlib's default, which is what the reference implementation
	// asks for; naming it keeps the two interoperating byte for byte.
	w, err := zlib.NewWriterLevel(&out, 6)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Inflate expands a zlib-formatted stream, refusing to produce more than
// limit bytes (a defence against compressed payloads that expand hugely).
func Inflate(b []byte, limit int) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: zlib: %v", ErrProtocol, err)
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", ErrProtocol, err)
	}
	if len(out) > limit {
		return nil, fmt.Errorf("%w: inflated payload over %d bytes", ErrProtocol, limit)
	}
	return out, nil
}

// Fragmenter splits instructions into fragments and reuses ids when the same
// instruction is sent twice, which is what lets the receiver deduplicate
// retransmissions.
type Fragmenter struct {
	nextID     uint64
	last       *ssp.Instruction
	lastMTU    int
	lastData   []byte
	lastAckVal uint64
	hasAck     bool
}

// LastAckNum reports the ack_num of the most recent instruction, which the
// session uses to notice that the peer sent its shutdown instruction.
func (fr *Fragmenter) LastAckNum() (uint64, bool) { return fr.lastAckVal, fr.hasAck }

// Make fragments a marshalled instruction to fit within mtu bytes per
// datagram payload.
func (fr *Fragmenter) Make(inst *ssp.Instruction, mtu int) ([][]byte, error) {
	if mtu <= FragmentHeaderBytes {
		return nil, fmt.Errorf("transport: MTU %d too small to fragment", mtu)
	}
	body, err := Compress(inst.Marshal())
	if err != nil {
		return nil, err
	}
	// Reuse the previous id when the instruction is unchanged, so that a
	// retransmission assembles against the same fragment set.
	if fr.last == nil || fr.lastMTU != mtu || !sameInstruction(fr.lastData, inst) {
		fr.nextID++
	}
	fr.last = inst
	fr.lastMTU = mtu
	fr.lastData = inst.Marshal()
	if inst.HasAckNum {
		fr.lastAckVal = inst.AckNum
		fr.hasAck = true
	}

	payloadPer := mtu - FragmentHeaderBytes
	var out [][]byte
	for i := 0; ; i += payloadPer {
		end := i + payloadPer
		final := end >= len(body)
		if final {
			end = len(body)
		}
		f := &Fragment{ID: fr.nextID, Num: uint16(i / payloadPer), Final: final, Contents: body[i:end]}
		if f.Num >= MaxFragments {
			return nil, fmt.Errorf("%w: too many fragments", ErrProtocol)
		}
		out = append(out, f.Marshal())
		if final {
			break
		}
	}
	if len(out) == 0 {
		// An empty instruction still needs one (final, empty) fragment.
		out = append(out, (&Fragment{ID: fr.nextID, Num: 0, Final: true}).Marshal())
	}
	return out, nil
}

func sameInstruction(a []byte, b *ssp.Instruction) bool {
	if a == nil {
		return false
	}
	return bytes.Equal(a, b.Marshal())
}
