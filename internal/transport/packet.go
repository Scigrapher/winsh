// Package transport implements mosh's UDP transport and State Synchronization
// Protocol (SSP) machinery: packet framing with sequence numbers and
// timestamps, zlib-compressed Instruction fragmentation and reassembly, the
// sliding-window sender with retransmission timers, and the receiver's state
// chain.
//
// The behaviour implemented here is the behaviour a mosh server expects on the
// wire: protocol version 2, direction/sequence encoded in the AES-OCB nonce,
// 16-octet fragment headers, and the same timer constants (frame rate from
// the smoothed round-trip time, 3 s empty-ack interval, 10 s active retry
// window).  It is written from that observable interface.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"winsh/internal/moshcrypto"
)

// Direction identifies which half of the session wrote a packet.  It is
// carried in the top bit of the nonce's sequence word, which is what stops a
// replayed client packet from being fed back to the client.
type Direction uint8

// Direction values.
const (
	ToServer Direction = 0
	ToClient Direction = 1
)

// Protocol overhead constants, mirroring the reference implementation.
const (
	// NetworkAddedBytes is the encrypted payload's timestamp pair plus the
	// nonce word that travels in front of the ciphertext.
	NetworkAddedBytes = 8 /* seqno/nonce */ + 4 /* timestamps */
	// FragmentHeaderBytes is the fragment id plus the numbered/final field.
	FragmentHeaderBytes = 8 + 2
)

// ErrProtocol reports a peer that is not speaking a compatible protocol.
var ErrProtocol = errors.New("transport: protocol violation")

// Packet is one decrypted SSP carrier: a directional sequence number, the
// two timestamps used for round-trip and frame-rate accounting, and the
// fragmented Instruction payload.
type Packet struct {
	Seq       uint64
	Direction Direction
	// Timestamp is the sender's clock in milliseconds, truncated to 16 bits.
	// 0xffff means "absent".
	Timestamp uint16
	// TimestampReply echoes a received Timestamp, advanced by the time the
	// sender held it.  0xffff means "absent".
	TimestampReply uint16
	Payload        []byte
}

// NoTimestamp is the sentinel value for an absent timestamp.
const NoTimestamp = uint16(0xffff)

// Clock returns the current 16-bit millisecond timestamp, matching the
// reference implementation's use of the low 16 bits of a millisecond clock.
func Clock() uint16 {
	return uint16(time.Now().UnixNano() / int64(time.Millisecond))
}

// TimestampDiff returns the forward distance from old to new in milliseconds,
// with 16-bit wraparound.
func TimestampDiff(newTS, oldTS uint16) uint16 {
	return newTS - oldTS
}

// word composes the nonce sequence word for a packet.
func word(d Direction, seq uint64) uint64 {
	var w uint64
	if d == ToClient {
		w = 1 << 63
	}
	return w | (seq & 0x7fffffffffffffff)
}

// Seal encrypts the packet into a datagram body.
func (p *Packet) Seal(s *moshcrypto.Session) ([]byte, error) {
	buf := make([]byte, 4+len(p.Payload))
	binary.BigEndian.PutUint16(buf[0:2], p.Timestamp)
	binary.BigEndian.PutUint16(buf[2:4], p.TimestampReply)
	copy(buf[4:], p.Payload)
	out, err := s.Encrypt(word(p.Direction, p.Seq), buf)
	if err != nil {
		return nil, fmt.Errorf("transport: seal: %w", err)
	}
	return out, nil
}

// OpenPacket decrypts a datagram body into a Packet.
func OpenPacket(s *moshcrypto.Session, datagram []byte) (*Packet, error) {
	w, plain, err := s.Decrypt(datagram)
	if err != nil {
		return nil, err
	}
	if len(plain) < 4 {
		return nil, fmt.Errorf("%w: short packet", ErrProtocol)
	}
	p := &Packet{
		Seq:            moshcrypto.WordSequence(w),
		Timestamp:      binary.BigEndian.Uint16(plain[0:2]),
		TimestampReply: binary.BigEndian.Uint16(plain[2:4]),
	}
	if moshcrypto.WordDirection(w) {
		p.Direction = ToClient
	}
	p.Payload = plain[4:]
	return p, nil
}
