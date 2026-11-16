// Package fakeserver is a minimal mosh server used by winsh's own tests and by
// "winsh --self-test".  It speaks the same wire protocol as mosh-server (SSP
// with AES-128-OCB) and behaves like a pty with local echo, which is enough to
// drive a client end to end without a real host.
//
// It is deliberately not a general-purpose server: there is no authentication
// beyond the session key (which is exactly what the real protocol uses), no
// command execution, and no PTY.
package fakeserver

import (
	"fmt"
	"net"
	"time"

	"winsh/internal/moshcrypto"
	"winsh/internal/state"
	"winsh/internal/stream"
	"winsh/internal/transport"
	"winsh/internal/vt"
)

// Server holds one fake session.
type Server struct {
	con *transport.Connection
	tr  *transport.Transport

	cols, rows int
	echo       bool
	// fed counts the input events already rendered, so re-delivered input is
	// not echoed twice.
	fed uint64
	// prompt is printed once the client has said hello.
	prompt string
}

// Options configures the fake server.
type Options struct {
	Cols, Rows int
	// Echo makes typed input appear on the screen, like a line discipline.
	Echo bool
	// LocalPort pins the UDP port; zero picks an ephemeral one.
	LocalPort int
	// Prompt is written to the screen after the first client packet.
	Prompt string
}

// New starts a fake server listening on addr (an address to bind, not a peer).
// The client's address is learned from the first authenticated datagram, which
// is how a real mosh server works.
func New(key moshcrypto.Key, bind *net.UDPAddr, opt Options) (*Server, error) {
	if opt.Cols < 1 {
		opt.Cols = 80
	}
	if opt.Rows < 1 {
		opt.Rows = 24
	}
	if bind == nil {
		bind = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}
	// The server starts detached: it only learns a peer when Attach is called
	// or, for a real mosh server, from the first authenticated datagram.
	con, err := transport.NewClientConnection(key, nil, transport.ConnOptions{
		BindIP:             bind.IP.String(),
		LocalPort:          opt.LocalPort,
		SendDirection:      transport.ToClient,
		ExpectDirection:    transport.ToServer,
		ExpectDirectionSet: true,
		AcceptRoaming:      true,
	})
	if err != nil {
		return nil, err
	}
	tr := transport.NewTransport(con, vt.NewTerminalState(opt.Cols, opt.Rows), &state.UserStream{})
	tr.Sender.SetSendDelay(time.Millisecond)
	return &Server{
		con:    con,
		tr:     tr,
		cols:   opt.Cols,
		rows:   opt.Rows,
		echo:   opt.Echo,
		prompt: opt.Prompt,
	}, nil
}

// Addr is the local UDP address clients should contact.
func (s *Server) Addr() *net.UDPAddr { return s.con.LocalAddr() }

// Port is the UDP port the server bound.
func (s *Server) Port() int {
	if a := s.con.LocalAddr(); a != nil {
		return a.Port
	}
	return 0
}

// Attach points the server at a client address (used by tests that know it up
// front, mirroring how mosh-server learns the client's address from packets).
func (s *Server) Attach(a *net.UDPAddr) { s.con.SetRemote(a) }

// Remote reports the address the server is currently replying to.
func (s *Server) Remote() *net.UDPAddr { return s.con.Remote() }

// ConnRoamedTo reports whether the server has followed the client to a.  After
// a client re-dials onto a new UDP 5-tuple this only becomes true once an
// authenticated, forward-moving datagram from the new address arrives, which is
// exactly the roaming rule mosh-server applies.
func (s *Server) ConnRoamedTo(a *net.UDPAddr) bool {
	r := s.con.Remote()
	return r != nil && a != nil && r.Port == a.Port && r.IP.Equal(a.IP)
}

// Close releases the socket and wipes the session key.
func (s *Server) Close() { s.con.Close() }

// ServeOnce receives everything queued, applies it, services timers, and
// reports whether new client input was consumed.
func (s *Server) ServeOnce(deadline time.Time) (bool, error) {
	got := false
	for {
		accepted, err := s.tr.Poll(deadline)
		if err != nil {
			return got, err
		}
		if accepted {
			got = true
			s.consumeInput()
		}
		if time.Now().After(deadline) {
			break
		}
		if !got {
			break
		}
	}
	if err := s.tr.Tick(); err != nil {
		return got, err
	}
	return got, nil
}

// Pump services the server for up to d, which is what a real server's event
// loop would do.
func (s *Server) Pump(d time.Duration) error {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if _, err := s.ServeOnce(time.Now().Add(5 * time.Millisecond)); err != nil {
			return err
		}
	}
	return nil
}

// consumeInput applies newly received keystrokes to the server's screen.
func (s *Server) consumeInput() {
	st, num, err := s.tr.LatestRemote()
	if err != nil {
		return
	}
	us, ok := st.(*state.UserStream)
	if !ok {
		return
	}
	_ = num
	// Feed everything we have not fed yet.
	if int(s.fed) >= len(us.Events) {
		return
	}
	for _, ev := range us.Events[s.fed:] {
		if ev.IsResize {
			s.cols, s.rows = int(ev.Width), int(ev.Height)
			s.tr.Sender.Push(func(st stream.State) {
				st.(*vt.TerminalState).Term.Resize(s.cols, s.rows)
			})
			continue
		}
		if !s.echo {
			continue
		}
		s.writeBytes([]byte{ev.Byte})
	}
	s.fed = uint64(len(us.Events))
}

// Feed makes the server print text, as a program on the far side of the pty
// would.
func (s *Server) Feed(b []byte) { s.writeBytes(b) }

// Printf makes the server print formatted text.
func (s *Server) Printf(format string, args ...any) {
	s.writeBytes([]byte(fmt.Sprintf(format, args...)))
}

func (s *Server) writeBytes(b []byte) {
	s.tr.Sender.Push(func(st stream.State) { st.(*vt.TerminalState).Feed(b) })
	s.tr.Sender.SetDataAck()
}

// LastSentNum reports the newest state the server has sent.
func (s *Server) LastSentNum() uint64 { return s.tr.Sender.SentStateLast() }

// StartShutdown begins the server side of the graceful-shutdown exchange.  This
// is what mosh-server does when the user's shell exits: from then on every
// instruction it sends carries new_num = 2^64-1, and the client is expected to
// acknowledge that and hang up.
func (s *Server) StartShutdown() { s.tr.Sender.StartShutdown() }

// ShutdownInProgress reports whether the server side has begun its own
// graceful-shutdown exchange.
func (s *Server) ShutdownInProgress() bool { return s.tr.Sender.ShutdownInProgress() }
