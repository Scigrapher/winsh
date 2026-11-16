package transport

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"winsh/internal/moshcrypto"
)

// Connection is the UDP half of a mosh session.
//
// Security-critical invariants, kept deliberately local to this file:
//
//   - Decryption happens only on the goroutine that calls NextPacket, so a
//     cipher session is touched by exactly one goroutine and the replay
//     counter cannot be raced.
//   - Datagrams that fail authentication are counted and dropped; nothing
//     about them is reflected back to the network.
//   - Received sequence numbers must not go backwards, which is what stops
//     replayed datagrams from disturbing the clock or (in the server half)
//     the client's pinned address.

// Timer and sizing constants from the mosh transport interface.
const (
	minRTO = 50 * time.Millisecond   /* retransmission floor */
	maxRTO = 1000 * time.Millisecond /* retransmission ceiling */

	// The application datagram size is chosen so that a 1280-byte IP packet
	// fits, because mobile and tunnelled paths routinely have low PMTUs and
	// mosh refuses to fragment.
	defaultIPv4MTU = 1280 - 20 - 8
	defaultIPv6MTU = 1280 - 40 - 16 - 8

	// portHopInterval is how long a client waits with no successful round
	// trip before it starts sending from a fresh local UDP port; that is how
	// mosh survives the client changing address or NAT binding.
	portHopInterval = 10 * time.Second
	maxPortsOpen    = 10
	maxOldSocketAge = 60 * time.Second

	// congestionPenalty slows the peer down when ECN marks a datagram.
	congestionPenalty = 500 * time.Millisecond

	// inboundQueueSize bounds the unauthenticated-datagram queue so a flood
	// cannot exhaust memory; excess datagrams are dropped on the floor.
	inboundQueueSize = 512
)

// ConnOptions tunes a client Connection.
type ConnOptions struct {
	// BindIP, if set, restricts sockets to that local address.
	BindIP string
	// LocalPort, if non-zero, pins the local UDP port.  Normal clients leave
	// it zero so that the OS picks an ephemeral port per socket.
	LocalPort int
	// Verbose writes socket churn to stderr.
	Verbose bool
	// SendDirection is the direction bit this connection stamps on outgoing
	// packets.  A client leaves it as ToServer; winsh's test server uses
	// ToClient.
	SendDirection Direction
	// ExpectDirection is the direction bit required on incoming packets.  A
	// client expects ToClient; a server expects ToServer.
	ExpectDirection Direction
	// ExpectDirectionSet must be true for ExpectDirection to be honoured;
	// it exists so the zero value keeps the client defaults.
	ExpectDirectionSet bool
	// AcceptRoaming makes this side follow the peer to a new address: any
	// authenticated, in-order datagram re-targets where replies go.  A mosh
	// server does this, and it is how a client that changed IP address or NAT
	// binding is picked up again.
	AcceptRoaming bool
}

type socket struct {
	conn      *net.UDPConn
	created   time.Time
	closed    atomic.Bool
	closeOnce sync.Once
}

func (s *socket) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

type inboundDatagram struct {
	data []byte
	src  *net.UDPAddr
}

// Connection carries encrypted SSP packets to and from one server.
type Connection struct {
	session *moshcrypto.Session
	remote  *net.UDPAddr
	opts    ConnOptions
	netName string // "udp4" or "udp6"
	mtu     int

	// seq is the outgoing packet sequence number.  It starts at zero, as in
	// the reference implementation, and strictly increases; Encrypt never
	// reuses a nonce.
	seq uint64

	savedTimestamp           uint16
	savedTimestampReceivedAt time.Time

	expectedReceiverSeq uint64

	srtt   float64
	rttvar float64
	rttHit bool

	lastPortChoice       time.Time
	lastRoundtripSuccess time.Time
	heardAt              time.Time

	sendErr error

	mu      sync.Mutex
	sockets []*socket
	inbound chan inboundDatagram
	closed  bool

	// notify carries a single-token "the inbound queue is probably non-empty"
	// signal.  It exists because the session loop blocks in a select on its
	// own input channel: a datagram arriving from the network has nothing else
	// to wake it with, so without this a reply could sit unread until some
	// timer happened to expire.  Capacity 1 plus a non-blocking send turns it
	// into a hint rather than a count, which is all a consumer needs: it
	// re-checks the queue and drains it.
	notify chan struct{}

	// dropFn, when set by a test, decides whether an outgoing payload is
	// discarded before transmission.  It exists so the loss-recovery paths can
	// be exercised deterministically.
	dropFn func(payload []byte) bool

	// Stats exposed for --verbose and for tests.
	RxTotal     uint64
	RxBadAuth   uint64
	RxDuplicate uint64
	TxTotal     uint64
	RxDropped   uint64
}

// NewClientConnection associates a UDP connection with the server at remote.
// NewClientConnection associates a UDP connection with the server at remote.
//
// remote may be nil, which creates a "server-shaped" connection that starts
// detached and locks onto a peer through SetRemote; winsh's own test harness
// uses that to emulate a mosh-server.
func NewClientConnection(key moshcrypto.Key, remote *net.UDPAddr, opts ConnOptions) (*Connection, error) {
	s, err := moshcrypto.NewSession(key)
	if err != nil {
		return nil, err
	}
	netName := "udp6"
	switch {
	case remote != nil && remote.IP.To4() != nil:
		netName = "udp4"
	case remote == nil && net.ParseIP(opts.BindIP).To4() != nil:
		// A detached (server-shaped) connection picks its family from the
		// address it was told to bind.
		netName = "udp4"
	}
	c := &Connection{
		session:              s,
		remote:               remote,
		opts:                 opts,
		netName:              netName,
		savedTimestamp:       NoTimestamp,
		srtt:                 1000,
		rttvar:               500,
		inbound:              make(chan inboundDatagram, inboundQueueSize),
		notify:               make(chan struct{}, 1),
		lastRoundtripSuccess: time.Now().Add(-time.Hour),
		lastPortChoice:       time.Now().Add(-time.Hour),
		expectedReceiverSeq:  0,
	}
	if _, err := c.addSocket(); err != nil {
		c.session.Destroy()
		return nil, err
	}
	return c, nil
}

// Backend reports the AES implementation protecting this connection.
func (c *Connection) Backend() string { return c.session.Backend() }

// Remote returns the peer address, or nil when detached.
func (c *Connection) Remote() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}

// SetRemote points the connection at a peer.  A mosh server does this when an
// authenticated datagram arrives from a new address: that is roaming.
func (c *Connection) SetRemote(a *net.UDPAddr) {
	c.mu.Lock()
	c.remote = a
	c.mu.Unlock()
}

// LocalAddr returns the local address of the socket the connection sends from.
func (c *Connection) LocalAddr() *net.UDPAddr {
	s := c.currentSocket()
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr().(*net.UDPAddr)
}

// MTU returns the largest payload the connection will put in one datagram.
func (c *Connection) MTU() int { return c.mtu }

// PayloadMTU returns the fragment budget: the datagram MTU minus the nonce
// word, the timestamp pair, and the OCB tag.
func (c *Connection) PayloadMTU() int { return c.mtu - NetworkAddedBytes - moshcrypto.AddedBytes }

// HasRemoteAddr reports whether the connection has a peer to talk to.
func (c *Connection) HasRemoteAddr() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote != nil
}

// Timeout returns the retransmission timeout derived from the smoothed RTT.
func (c *Connection) Timeout() time.Duration {
	rto := time.Duration(math.Ceil(c.srtt+4*c.rttvar)) * time.Millisecond
	if rto < minRTO {
		rto = minRTO
	}
	if rto > maxRTO {
		rto = maxRTO
	}
	return rto
}

// SRTT returns the smoothed round-trip time in milliseconds.
func (c *Connection) SRTT() float64 { return c.srtt }

// SendError returns and clears the last socket-level send failure, which the
// frontend surfaces as a network-error notification.
func (c *Connection) SendError() string {
	e := c.sendErr
	c.sendErr = nil
	if e == nil {
		return ""
	}
	return e.Error()
}

// LastRoundtripSuccess returns the time of the last state the peer
// acknowledged, used by the port-hopping rule.
func (c *Connection) LastRoundtripSuccess() time.Time { return c.lastRoundtripSuccess }

// SetLastRoundtripSuccess records an acknowledged round trip.
func (c *Connection) SetLastRoundtripSuccess(t time.Time) { c.lastRoundtripSuccess = t }

func (c *Connection) addSocket() (*socket, error) {
	var addr *net.UDPAddr
	if c.opts.LocalPort != 0 || c.opts.BindIP != "" {
		addr = &net.UDPAddr{IP: net.ParseIP(c.opts.BindIP), Port: c.opts.LocalPort}
		if addr.IP == nil && c.opts.BindIP != "" {
			return nil, fmt.Errorf("transport: bad bind address %q", c.opts.BindIP)
		}
	}
	conn, err := net.ListenUDP(c.netName, addr)
	if err != nil {
		return nil, fmt.Errorf("transport: listen udp: %w", err)
	}
	if c.mtu == 0 {
		if ip := conn.LocalAddr().(*net.UDPAddr).IP; ip.To4() != nil {
			c.mtu = defaultIPv4MTU
		} else {
			c.mtu = defaultIPv6MTU
		}
	}
	s := &socket{conn: conn, created: time.Now()}
	c.mu.Lock()
	c.sockets = append(c.sockets, s)
	c.lastPortChoice = time.Now()
	if len(c.sockets) > maxPortsOpen {
		drop := c.sockets[:len(c.sockets)-maxPortsOpen]
		c.sockets = c.sockets[len(drop):]
		c.mu.Unlock()
		for _, old := range drop {
			old.Close()
		}
	} else {
		c.mu.Unlock()
	}
	go c.readLoop(s)
	return s, nil
}

func (c *Connection) readLoop(s *socket) {
	buf := make([]byte, moshcrypto.ReceiveMTU)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed or dead
		}
		if n <= 0 || s.closed.Load() {
			continue
		}
		dup := make([]byte, n)
		copy(dup, buf[:n])
		select {
		case c.inbound <- inboundDatagram{data: dup, src: src}:
			// Signalled only after a successful enqueue, so a consumer that
			// drained the queue just before this point still sees the token
			// and rechecks.
			c.signalData()
		default:
			// Queue full: drop rather than grow without bound.  SSP's
			// retransmission timers recover the loss.
			atomic.AddUint64(&c.RxDropped, 1)
		}
	}
}

// currentSocket returns the newest socket, which is the one the client sends
// from so that a roaming client presents a fresh 5-tuple.
func (c *Connection) currentSocket() *socket {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sockets) == 0 {
		return nil
	}
	return c.sockets[len(c.sockets)-1]
}

// Send encrypts payload as one SSP packet and transmits it on the current
// socket.  Each call consumes a new sequence number, so a nonce is never
// reused.
func (c *Connection) Send(payload []byte) error {
	sock := c.currentSocket()
	if sock == nil {
		if _, err := c.addSocket(); err != nil {
			return err
		}
		sock = c.currentSocket()
	}
	p := &Packet{
		Seq:            c.seq,
		Direction:      c.opts.SendDirection,
		Timestamp:      Clock(),
		TimestampReply: c.timestampReply(),
		Payload:        payload,
	}
	c.seq++
	datagram, err := p.Seal(c.session)
	if err != nil {
		return err
	}
	if c.dropFn != nil && c.dropFn(payload) {
		return nil
	}
	remote := c.Remote()
	if remote == nil {
		return errors.New("transport: connection detached from peer")
	}
	if _, err := sock.conn.WriteToUDP(datagram, remote); err != nil {
		c.sendErr = err
		return err
	}
	atomic.AddUint64(&c.TxTotal, 1)
	c.maybeHopPort()
	return nil
}

// timestampReply returns the peer's last timestamp advanced by the time we
// have held it, or NoTimestamp if we have nothing recent.
func (c *Connection) timestampReply() uint16 {
	if c.savedTimestamp == NoTimestamp {
		return NoTimestamp
	}
	held := time.Since(c.savedTimestampReceivedAt)
	if held >= time.Second {
		c.savedTimestamp = NoTimestamp
		return NoTimestamp
	}
	return c.savedTimestamp + uint16(held/time.Millisecond)
}

// maybeHopPort starts sending from a new local port when the session has been
// silent for too long, which is how a roaming client gets the server to
// re-target it.
func (c *Connection) maybeHopPort() {
	now := time.Now()
	if now.Sub(c.lastPortChoice) < portHopInterval {
		return
	}
	if now.Sub(c.lastRoundtripSuccess) < portHopInterval {
		return
	}
	if _, err := c.addSocket(); err != nil {
		c.sendErr = err
		return
	}
	c.pruneSockets(now)
}

func (c *Connection) pruneSockets(now time.Time) {
	c.mu.Lock()
	if len(c.sockets) > 1 && now.Sub(c.lastPortChoice) > maxOldSocketAge {
		keep := c.sockets[len(c.sockets)-1]
		drop := c.sockets[:len(c.sockets)-1]
		c.sockets = []*socket{keep}
		c.mu.Unlock()
		for _, old := range drop {
			old.Close()
		}
		return
	}
	c.mu.Unlock()
}

// NextPacket blocks until an authenticated packet arrives or deadline passes.
// It returns nil when the deadline expires.  The second result is the source
// address of the accepted packet.
func (c *Connection) NextPacket(deadline time.Time) (*Packet, *net.UDPAddr, error) {
	for {
		// Serve anything already queued before looking at the deadline, so a
		// caller that polls with a past deadline still drains the queue.
		d, ok, err := c.tryReceive()
		if err != nil {
			return nil, nil, err
		}
		if ok {
			if pkt := c.open(d); pkt != nil {
				return pkt, d.src, nil
			}
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil, nil
		}
		timer := time.NewTimer(remaining)
		select {
		case nd, ok := <-c.inbound:
			timer.Stop()
			if !ok {
				return nil, nil, errors.New("transport: connection closed")
			}
			if pkt := c.open(nd); pkt != nil {
				return pkt, nd.src, nil
			}
		case <-timer.C:
			return nil, nil, nil
		}
	}
}

// signalData publishes the "data may be waiting" hint without ever blocking a
// reader; the socket goroutine must never stall on a busy consumer.
func (c *Connection) signalData() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// DataReady returns the channel that receives a token whenever a datagram has
// been queued.  A select case on it is a hint, not a guarantee: the receiver
// still has to drain the queue.  It is intentionally never closed, so a
// shutdown does not turn into a busy loop; callers select on their own stop
// channel as well.
func (c *Connection) DataReady() <-chan struct{} { return c.notify }

// tryReceive reports whether a datagram is already buffered.
func (c *Connection) tryReceive() (inboundDatagram, bool, error) {
	select {
	case d, ok := <-c.inbound:
		if !ok {
			return inboundDatagram{}, false, errors.New("transport: connection closed")
		}
		return d, true, nil
	default:
		return inboundDatagram{}, false, nil
	}
}

// open decrypts one datagram, dropping anything that fails authentication.
func (c *Connection) open(d inboundDatagram) *Packet {
	pkt, err := OpenPacket(c.session, d.data)
	if err != nil {
		atomicAdd(&c.RxBadAuth, 1)
		return nil
	}
	atomicAdd(&c.RxTotal, 1)
	if c.opts.ExpectDirectionSet {
		if pkt.Direction != c.opts.ExpectDirection {
			atomicAdd(&c.RxBadAuth, 1)
			return nil
		}
	} else if pkt.Direction != ToClient {
		// A datagram aimed at the server, replayed at us: drop it and leave
		// the replay window untouched.
		atomicAdd(&c.RxBadAuth, 1)
		return nil
	}
	c.noteReceived(pkt, d.src)
	return pkt
}

func atomicAdd(p *uint64, n uint64) { atomic.AddUint64(p, n) }

// noteReceived applies the replay and round-trip bookkeeping for one accepted
// packet.
func (c *Connection) noteReceived(p *Packet, src *net.UDPAddr) {
	if p.Seq < c.expectedReceiverSeq {
		atomic.AddUint64(&c.RxDuplicate, 1)
		// Out-of-order/duplicate payloads are still handed up: SSP is
		// idempotent by construction, and dropping them would stall recovery.
		// But they must not move the clock or the address, so return now.
		return
	}
	c.expectedReceiverSeq = p.Seq + 1

	if p.Timestamp != NoTimestamp {
		c.savedTimestamp = p.Timestamp
		c.savedTimestampReceivedAt = time.Now()
	}
	if c.opts.AcceptRoaming && src != nil {
		if cur := c.Remote(); cur == nil || cur.String() != src.String() {
			c.SetRemote(src)
		}
	}
	if p.TimestampReply != NoTimestamp {
		r := float64(TimestampDiff(Clock(), p.TimestampReply))
		if r < 5000 { // ignore stale measurements (e.g. after a suspend)
			if !c.rttHit {
				c.srtt = r
				c.rttvar = r / 2
				c.rttHit = true
			} else {
				const alpha, beta = 1.0 / 8.0, 1.0 / 4.0
				c.rttvar = (1-beta)*c.rttvar + beta*math.Abs(c.srtt-r)
				c.srtt = (1-alpha)*c.srtt + alpha*r
			}
			_ = src
		}
	}
	c.heardAt = time.Now()
}

// LastHeard returns when the last authenticated packet arrived.
func (c *Connection) LastHeard() time.Time { return c.heardAt }

// Close shuts down all sockets and wipes key material.
func (c *Connection) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	socks := c.sockets
	c.sockets = nil
	c.mu.Unlock()
	for _, s := range socks {
		s.Close()
	}
	close(c.inbound)
	c.session.Destroy()
	return nil
}

// Redial replaces every socket with a fresh one, keeping the sequence-number
// counter, the replay window, and the round-trip estimates.  A mosh server
// only re-targets its address for datagrams whose sequence numbers move
// forward, so the counter must survive: creating a brand-new Connection to
// "reconnect" would be rejected as replay.  This is also what port hopping
// uses.
func (c *Connection) Redial() error {
	c.mu.Lock()
	old := c.sockets
	c.sockets = nil
	c.mu.Unlock()
	for _, s := range old {
		s.Close()
	}
	// Clear the MTU first: addSocket derives it from the new socket's address
	// family, and a stale or zero value would break fragment sizing.
	c.mtu = 0
	if _, err := c.addSocket(); err != nil {
		return err
	}
	if c.currentSocket() == nil {
		return errors.New("transport: redial left no socket")
	}
	return nil
}
