package transport

import (
	"fmt"
	"os"
	"time"

	"winsh/internal/ssp"
)

// Transport pairs a Connection with a sender and a receiver, which is the
// shape the mosh protocol has: both directions carry versioned state updates,
// and each direction acknowledges the other's.
type Transport struct {
	Conn     *Connection
	Sender   *Sender
	Receiver *Receiver

	fragments Assembly
	verbose   bool
}

// NewTransport builds a transport whose local stream starts at myState and
// whose view of the peer's stream starts at initialRemote.
func NewTransport(conn *Connection, myState, initialRemote State) *Transport {
	return &Transport{
		Conn:     conn,
		Sender:   NewSender(conn, myState),
		Receiver: NewReceiver(initialRemote),
	}
}

// SetVerbose enables per-packet diagnostics on the sender.
func (t *Transport) SetVerbose(v bool) { t.verbose = v; t.Sender.SetVerbose(v) }

// WaitTime returns how long the caller may block before the next service
// opportunity, taking both the sender's timers and an external hint (the
// terminal echo-ack timer, for instance) into account.
// A negative extra means "no external hint".  Passing 0 would otherwise be
// indistinguishable from a hint that says "wake immediately", which silently
// pinned every caller to the busy end of the range.  The -1 (idle) and 0
// (due now) sentinels from Sender.WaitTime are preserved so that the caller
// can tell them apart.
func (t *Transport) WaitTime(extra time.Duration) time.Duration {
	return mergeWait(t.Sender.WaitTime(), extra)
}

// mergeWait folds an external hint into the sender's answer.  Split out so the
// sentinel handling is testable on its own: the hint used to be compared with
// "extra >= 0", which made the caller's conventional "no hint" value of 0 look
// like an instruction to wake immediately.
func mergeWait(d, extra time.Duration) time.Duration {
	if extra >= 0 && (d < 0 || extra < d) {
		d = extra
	}
	return d
}

// Tick services the sender's timers.
func (t *Transport) Tick() error { return t.Sender.Tick() }

// Poll receives one datagram until deadline and processes any instruction it
// completes.  It reports whether new peer state was accepted.
func (t *Transport) Poll(deadline time.Time) (bool, error) {
	pkt, _, err := t.Conn.NextPacket(deadline)
	if err != nil || pkt == nil {
		return false, err
	}
	return t.handlePacket(pkt)
}

// Drain processes every datagram that has already arrived and authenticated,
// without blocking.  It returns how many datagrams were consumed, which lets
// the caller tell "queue empty" apart from "packet with no new state".
func (t *Transport) Drain() (int, error) {
	count := 0
	for {
		d, ok, err := t.Conn.tryReceive()
		if err != nil {
			return count, err
		}
		if !ok {
			return count, nil
		}
		pkt := t.Conn.open(d)
		if pkt == nil {
			continue
		}
		count++
		if _, err := t.handlePacket(pkt); err != nil {
			return count, err
		}
		if count >= 256 {
			// Fairness: hand control back so input and timers are not
			// starved by a flood.
			return count, nil
		}
	}
}

func (t *Transport) handlePacket(pkt *Packet) (bool, error) {
	frag, err := ParseFragment(pkt.Payload)
	if err != nil {
		if t.verbose {
			fmt.Fprintf(os.Stderr, "winsh: dropped fragment: %v\n", err)
		}
		return false, nil
	}
	complete, err := t.fragments.Add(frag)
	if err != nil {
		if t.verbose {
			fmt.Fprintf(os.Stderr, "winsh: fragment assembly error: %v\n", err)
		}
		return false, nil
	}
	if !complete {
		return false, nil
	}
	inst, err := t.fragments.Instruction()
	if err != nil {
		if t.verbose {
			fmt.Fprintf(os.Stderr, "winsh: instruction decode error: %v\n", err)
		}
		return false, nil
	}
	if !inst.HasProtocol || inst.ProtocolVersion != ssp.ProtocolVersion {
		return false, ErrProtocol
	}
	t.Sender.ProcessAcknowledgmentThrough(inst.AckNum)
	t.Conn.SetLastRoundtripSuccess(t.Sender.SentStateAckedTimestamp())

	accepted, err := t.Receiver.ProcessInstruction(inst)
	if err != nil {
		return false, err
	}
	if accepted {
		newest, err := t.Receiver.Latest()
		if err != nil {
			return false, err
		}
		t.Sender.SetAckNum(newest.Num)
		t.Sender.RemoteHeard(newest.Timestamp)
		if len(inst.Diff) > 0 {
			t.Sender.SetDataAck()
		}
	}
	return accepted, nil
}

// LatestRemote returns the newest materialized peer state.
func (t *Transport) LatestRemote() (State, uint64, error) { return t.Receiver.Deliver() }

// PollNow processes any already-arrived datagram without waiting, which lets a
// caller drive its own select loop over sockets and timers.
func (t *Transport) PollNow() (bool, error) { return t.Poll(time.Now()) }
