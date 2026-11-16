package ssh

import (
	"errors"
	"fmt"
	"io"
)

// Channel is an SSH "session" channel used to run mosh-server.

// maxWindow is the flow-control window winsh advertises.  It is large enough
// that a bootstrap never stalls, and window updates are sent as bytes are
// consumed so a long-running command cannot deadlock either.
const maxWindow = 2 * 1024 * 1024

// maxChannelBuffer and maxChannelReplies are hard local caps in addition to
// the peer's advertised flow-control window. A broken or hostile server must
// not be able to grow client memory merely by ignoring window updates.
const (
	maxChannelBuffer  = maxWindow
	maxChannelReplies = 64
)

// OpenSession opens a session channel.
func (c *Client) OpenSession() (*Channel, error) {
	id := c.nextChan
	c.nextChan++
	var o builder
	o.byte_(msgChannelOpen)
	o.str([]byte("session"))
	o.uint32(id)
	o.uint32(maxWindow)
	o.uint32(32 * 1024)
	if err := c.writePacket(o.b); err != nil {
		return nil, err
	}
	for {
		p, err := c.expect(msgChannelOpenConfirm, msgChannelOpenFailure, msgGlobalRequest)
		if err != nil {
			return nil, err
		}
		switch p[0] {
		case msgGlobalRequest:
			// Winsh asks for nothing; reply failure so the server stops.
			m := &msg{b: p[1:]}
			if _, ok := m.str(); !ok {
				return nil, m.err
			}
			if wantReply, ok := m.boolv(); ok && wantReply {
				var r builder
				r.byte_(msgRequestFailure)
				if err := c.writePacket(r.b); err != nil {
					return nil, err
				}
			}
			continue
		case msgChannelOpenFailure:
			m := &msg{b: p[1:]}
			if _, ok := m.uint32(); !ok {
				return nil, m.err
			}
			reason, _ := m.uint32()
			desc, _ := m.str()
			return nil, fmt.Errorf("%w: %d %s", ErrChannelRejected, reason, desc)
		}
		m := &msg{b: p[1:]}
		_, _ = m.uint32() // sender channel echoed back
		remoteID, ok := m.uint32()
		if !ok {
			return nil, m.err
		}
		recvWin, ok := m.uint32()
		if !ok {
			return nil, m.err
		}
		maxPkt, ok := m.uint32()
		if !ok {
			return nil, m.err
		}
		ch := &Channel{id: id, remoteID: remoteID, recvWin: recvWin, maxPacket: maxPkt, c: c}
		if ch.maxPacket == 0 || ch.maxPacket > 256*1024 {
			ch.maxPacket = 32 * 1024
		}
		c.channels[id] = ch
		return ch, nil
	}
}

// RequestPty asks the server to attach a terminal, as mosh's wrapper does with
// ssh -tt.
func (ch *Channel) RequestPty(term string, cols, rows int) error {
	var modes builder
	modes.byte_(1) // TTY_OP_ISPEED
	modes.uint32(38400)
	modes.byte_(2) // TTY_OP_OSPEED
	modes.uint32(38400)
	modes.byte_(0) // end

	var o builder
	o.byte_(msgChannelRequest)
	o.uint32(ch.id)
	o.str([]byte("pty-req"))
	o.boolv(true)
	o.str([]byte(term))
	o.uint32(uint32(cols))
	o.uint32(uint32(rows))
	o.uint32(0)
	o.uint32(0)
	o.str(modes.b)
	if err := ch.c.writePacket(o.b); err != nil {
		return err
	}
	// pty-req asks for a reply, so it has to be collected here rather
	// than surprising the channel reader later.
	return ch.waitReply("pty-req")
}

// SetEnv sends an env request (used for LANG, like mosh's -l flags).
func (ch *Channel) SetEnv(name, value string) error {
	var o builder
	o.byte_(msgChannelRequest)
	o.uint32(ch.id)
	o.str([]byte("env"))
	o.boolv(false)
	o.str([]byte(name))
	o.str([]byte(value))
	return ch.c.writePacket(o.b)
}

// waitReply consumes the CHANNEL_SUCCESS or CHANNEL_FAILURE that answers a
// channel request sent with want-reply set. Skipping this is not harmless: the
// reply is queued on the connection, and the next reader that is not expecting
// it -- usually the channel-data pump -- has to decide what to do with it.
func (ch *Channel) waitReply(what string) error {
	for {
		if len(ch.replies) > 0 {
			kind := ch.replies[0]
			ch.replies = ch.replies[1:]
			if kind == msgChannelFailure {
				return fmt.Errorf("%w: server refused the %s request", ErrChannelRejected, what)
			}
			return nil
		}
		if ch.closed {
			return fmt.Errorf("%w: channel closed before the %s request was answered", ErrDisconnected, what)
		}
		if err := ch.pump(); err != nil {
			return err
		}
	}
}

// Exec runs a command on the channel.
func (ch *Channel) Exec(command string) error {
	var o builder
	o.byte_(msgChannelRequest)
	o.uint32(ch.id)
	o.str([]byte("exec"))
	o.boolv(true)
	o.str([]byte(command))
	if err := ch.c.writePacket(o.b); err != nil {
		return err
	}
	// exec sets want-reply, and if the server could not run the command this
	// is the only place it will tell us.
	return ch.waitReply("exec")

}

const (
	extendedStderr = 1
)

// Read returns stdout data, buffering internally; io.EOF means the channel was
// closed by the server.
func (ch *Channel) Read(p []byte) (int, error) {
	// Keep pumping until there is something to hand back. A single pump can
	// legitimately return with nothing buffered -- it may have consumed a
	// request reply or a window adjustment -- and treating that as end-of-file
	// truncates the session at the first such packet.
	for len(ch.buf) == 0 {
		if ch.eof || ch.closed {
			return 0, io.EOF
		}
		if err := ch.pump(); err != nil {
			return 0, err
		}
	}
	if len(ch.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, ch.buf)
	ch.buf = ch.buf[n:]
	ch.consumed += uint32(n)
	if ch.consumed > maxWindow/2 {
		if err := ch.adjustWindow(ch.consumed); err != nil {
			return n, err
		}
		ch.consumed = 0
	}
	return n, nil
}

func (ch *Channel) adjustWindow(n uint32) error {
	var o builder
	o.byte_(msgChannelWindowAdjust)
	o.uint32(ch.id)
	o.uint32(n)
	return ch.c.writePacket(o.b)
}

// pump reads one packet addressed to this channel.
func (ch *Channel) pump() error {
	for {
		p, err := ch.c.readPacket()
		if err != nil {
			return err
		}
		if len(p) == 0 {
			return errors.New("ssh: empty packet")
		}
		m := &msg{b: p[1:]}
		switch p[0] {
		case msgDisconnect:
			code, _ := m.uint32()
			desc, _ := m.str()
			return &Error{Code: int(code), Message: string(desc)}
		case msgIgnore, msgUnimplemented, msgDebug, msgGlobalRequest:
			continue
		case msgChannelData, msgChannelExtendedData:
			id, ok := m.uint32()
			if !ok {
				return m.err
			}
			if id != ch.id {
				continue
			}
			if p[0] == msgChannelExtendedData {
				// stderr: keep the most recent kilobyte for diagnostics.
				kind, _ := m.uint32()
				data, ok := m.str()
				if !ok {
					return m.err
				}
				if kind == extendedStderr {
					ch.stderr = append(ch.stderr, data...)
					if len(ch.stderr) > 8192 {
						ch.stderr = ch.stderr[len(ch.stderr)-8192:]
					}
				}
				continue
			}
			data, ok := m.str()
			if !ok {
				return m.err
			}
			if len(data) > maxPacketBytes {
				return errors.New("ssh: over-long channel data")
			}
			if err := ch.appendData(data); err != nil {
				return err
			}
			return nil
		case msgChannelWindowAdjust:
			id, ok := m.uint32()
			if !ok {
				return m.err
			}
			inc, ok := m.uint32()
			if !ok {
				return m.err
			}
			if id == ch.id {
				ch.recvWin += inc
			}
			continue
		case msgChannelEOF:
			id, _ := m.uint32()
			if id == ch.id {
				ch.eof = true
				if len(ch.buf) > 0 {
					return nil
				}
				return io.EOF
			}
			continue
		case msgChannelClose:
			id, _ := m.uint32()
			if id == ch.id {
				ch.closed = true
				ch.eof = true
				if len(ch.buf) > 0 {
					return nil
				}
				return io.EOF
			}
		// A request we sent with want-reply set is answered by SUCCESS or
		// FAILURE. Requests that ask for a reply wait for it (see
		// waitReply), but a reply can still surface here -- for instance one
		// for a request whose reply raced with the first data packet -- and
		// treating it as an unknown message kills a working session.
		case msgChannelSuccess, msgChannelFailure:
			// Answer to a channel request we sent with want-reply set.
			// Queue it and hand control back: pump loops, so returning here
			// is what lets waitReply see the reply at all. Swallowing it in
			// the loop instead deadlocks the bootstrap, because the server
			// then sits waiting for the exec that never gets sent.
			if len(p) >= 5 {
				rm := &msg{b: p[1:]}
				if id, ok := rm.uint32(); ok && id == ch.remoteID {
					if len(ch.replies) >= maxChannelReplies {
						return errors.New("ssh: too many queued channel replies")
					}
					ch.replies = append(ch.replies, p[0])
					return nil
				}
			}
			continue
		case msgChannelRequest:
			// The server may send keepalive requests; ignore them.
			continue
		default:
			return fmt.Errorf("%w: unexpected message %d in channel read", ErrUnsupported, p[0])
		}
	}
}

func (ch *Channel) appendData(data []byte) error {
	if len(data) > maxChannelBuffer || len(ch.buf) > maxChannelBuffer-len(data) {
		return errors.New("ssh: channel receive buffer limit exceeded")
	}
	ch.buf = append(ch.buf, data...)
	return nil
}

// Stderr returns the most recent stderr bytes seen on this channel.
// StdoutBuffered returns data received but not yet handed to a reader.
func (ch *Channel) StdoutBuffered() []byte { return append([]byte(nil), ch.buf...) }

func (ch *Channel) Stderr() []byte { return append([]byte(nil), ch.stderr...) }

// Close closes the channel.
func (ch *Channel) Close() error {
	var o builder
	o.byte_(msgChannelClose)
	o.uint32(ch.id)
	return ch.c.writePacket(o.b)
}
