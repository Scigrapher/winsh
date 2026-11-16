package transport

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"winsh/internal/ssp"
	"winsh/internal/stream"
)

// The State Synchronization Protocol half of winsh: a sliding window of
// versioned states in each direction, where an update is a diff from some
// earlier state plus the number of the state the sender believes the receiver
// has.  That design is what makes mosh tolerant of loss, reordering, and a
// client that disappears and comes back with a new address.

// SSP timer constants, as the reference implementation defines them.
const (
	sendIntervalMin = 20 * time.Millisecond   /* fastest frame rate */
	sendIntervalMax = 250 * time.Millisecond  /* slowest frame rate */
	ackInterval     = 3000 * time.Millisecond /* between empty acknowledgments */
	ackDelay        = 100 * time.Millisecond  /* delayed-ack window */
	shutdownRetries = 16
	// shutdownGrace is how long the client keeps re-offering its shutdown
	// instruction before handing the terminal back regardless.
	shutdownGrace = 3000 * time.Millisecond
	// shutdownRetry is the gap between re-offers of the shutdown instruction.
	shutdownRetry      = 250 * time.Millisecond
	activeRetryTimeout = 10000 * time.Millisecond

	maxSentStates        = 32
	maxReceivedStates    = 1024
	maxReceiverDiffBytes = 32 << 20
	receiverQuenchPause  = 15000 * time.Millisecond
	materializedCache    = 16

	// chaffMax is how many random bytes are appended to an instruction so
	// that packet sizes leak less about the content.
	chaffMax = 16
)

// noNum is the sentinel the protocol uses for "shutting down".
const noNum = ^uint64(0)

// State is a synchronizable stream: the client's input events, or the
// server's terminal.  It is defined in package stream so that the emulator and
// the input stream need not depend on this package.
type State = stream.State

// TimestampedState is one entry of a sender's or receiver's state window.
type TimestampedState struct {
	Timestamp time.Time
	Num       uint64
	S         State
}

// Sender implements the sending half: it owns the current state, remembers the
// states it has transmitted, and retransmits whatever the receiver has not
// acknowledged.
type Sender struct {
	conn        *Connection
	current     State
	sent        []*TimestampedState
	assumedRecv int
	fragmenter  Fragmenter

	nextAckTime  time.Time
	nextSendTime time.Time
	mindelay     time.Time
	hasMindelay  bool

	shutdownInProgress bool
	shutdownTries      int
	shutdownStart      time.Time

	ackNum         uint64
	pendingDataAck bool
	sendMinDelay   time.Duration
	lastHeard      time.Time

	verbose bool
}

// NewSender returns a sender whose initial state is the one the receiver is
// assumed to start from.
func NewSender(conn *Connection, initial State) *Sender {
	now := time.Now()
	s0 := &TimestampedState{Timestamp: now, Num: 0, S: initial.Clone()}
	return &Sender{
		conn:         conn,
		current:      initial.Clone(),
		sent:         []*TimestampedState{s0},
		assumedRecv:  0,
		nextAckTime:  now,
		nextSendTime: now,
		sendMinDelay: 8 * time.Millisecond,
		ackNum:       0,
	}
}

// SetSendDelay sets how long the sender collects input before sending.
func (s *Sender) SetSendDelay(d time.Duration) { s.sendMinDelay = d }

// SetVerbose turns on per-packet diagnostics.
func (s *Sender) SetVerbose(v bool) { s.verbose = v }

// Current returns the state the sender is trying to deliver.
func (s *Sender) Current() State { return s.current }

// Push applies a mutation to the current state through fn.  Splitting it this
// way keeps callers from holding a reference that the window may later
// rewrite with Subtract.
func (s *Sender) Push(fn func(State)) {
	fn(s.current)
}

// StartShutdown begins the graceful-shutdown exchange, in which every packet
// carries new_num = -1 until the peer acknowledges it.
func (s *Sender) StartShutdown() {
	if !s.shutdownInProgress {
		s.shutdownStart = time.Now()
		s.shutdownInProgress = true
	}
}

// ShutdownInProgress reports whether the session is winding down.
func (s *Sender) ShutdownInProgress() bool { return s.shutdownInProgress }

// ShutdownAckTimedOut reports that the peer never answered the shutdown.
func (s *Sender) ShutdownAckTimedOut() bool {
	if !s.shutdownInProgress {
		return false
	}
	if s.shutdownTries >= shutdownRetries {
		return true
	}
	// Deliberately not activeRetryTimeout.  That constant is the patience a
	// client shows a *running* session whose packets have stopped; applying it
	// to a shutdown the user asked for leaves the terminal frozen on
	// "Exiting..." for ten seconds after a single lost reply.  Three seconds is
	// far more than a healthy round trip needs and never reads as a hang.
	return time.Since(s.shutdownStart) >= shutdownGrace
}

// ShutdownAcknowledged reports that the front of the window is the shutdown
// state, i.e. the peer has acked new_num = -1.
func (s *Sender) ShutdownAcknowledged() bool {
	return len(s.sent) > 0 && s.sent[0].Num == noNum
}

// CounterpartyShutdownAcknowledged reports that the peer told us (through the
// fragmenter) that it sent its own shutdown instruction.
func (s *Sender) CounterpartyShutdownAcknowledged() bool {
	ack, ok := s.fragmenter.LastAckNum()
	return ok && ack == noNum
}

// SetAckNum records what the receiver says it has.
func (s *Sender) SetAckNum(n uint64) { s.ackNum = n }

// SetDataAck requests a prompt acknowledgment because new data arrived.
func (s *Sender) SetDataAck() { s.pendingDataAck = true }

// RemoteHeard records that a new remote state arrived at t.
func (s *Sender) RemoteHeard(t time.Time) { s.lastHeard = t }

// SentStateAckedTimestamp returns when the front (fully acknowledged) state
// was first sent, which the connection uses as a round-trip success marker.
func (s *Sender) SentStateAckedTimestamp() time.Time {
	if len(s.sent) == 0 {
		return time.Time{}
	}
	return s.sent[0].Timestamp
}

// SentStateAcked returns the state number fully acknowledged by the peer.
func (s *Sender) SentStateAcked() uint64 {
	if len(s.sent) == 0 {
		return 0
	}
	return s.sent[0].Num
}

// SentStateLast returns the highest state number ever sent.
func (s *Sender) SentStateLast() uint64 {
	if len(s.sent) == 0 {
		return 0
	}
	return s.sent[len(s.sent)-1].Num
}

// SendInterval is the frame rate: half a round trip, clamped.
func (s *Sender) SendInterval() time.Duration {
	d := time.Duration(math.Ceil(s.conn.SRTT()/2)) * time.Millisecond
	if d < sendIntervalMin {
		d = sendIntervalMin
	}
	if d > sendIntervalMax {
		d = sendIntervalMax
	}
	return d
}

// WaitTime returns how long the caller may sleep before the next Tick must
// run.  The result is deliberately three-valued, and callers must not collapse
// the first two cases:
//
//	-1  nothing is scheduled; the caller may idle until an event arrives
//	 0  a timer is already due; Tick has to run before the loop blocks again
//	 >0 sleep for at most this long
//
// Unset timers are the zero time, so they are skipped rather than compared:
// time.Until on a zero time is hugely negative and would otherwise read as
// "due now" forever.
func (s *Sender) WaitTime() time.Duration {
	s.calculateTimers()
	if !s.conn.HasRemoteAddr() {
		return -1
	}
	return waitTimeFrom(s.nextAckTime, s.nextSendTime)
}

// waitTimeFrom maps the two send timers onto the three-valued answer the event
// loop expects.  It is factored out of WaitTime so the mapping itself can be
// tested directly: the failure it guards against was a confusion between
// "nothing is scheduled" and "a timer is due right now", both of which used to
// reach the caller as a non-positive number and were then slept off as a whole
// second.
//
// An unset timer is the zero time and must be skipped rather than compared,
// because time.Until of the zero time is hugely negative and would look like
// "due now" forever.
func waitTimeFrom(nextAck, nextSend time.Time) time.Duration {
	var next time.Time
	if !nextAck.IsZero() {
		next = nextAck
	}
	if !nextSend.IsZero() && (next.IsZero() || nextSend.Before(next)) {
		next = nextSend
	}
	if next.IsZero() {
		return -1
	}
	if d := time.Until(next); d > 0 {
		return d
	}
	return 0
}

func (s *Sender) updateAssumedReceiverState() {
	now := time.Now()
	// Everything transmitted recently enough ago is assumed received.
	s.assumedRecv = 0
	for i := 1; i < len(s.sent); i++ {
		if now.Sub(s.sent[i].Timestamp) < s.conn.Timeout()+ackDelay {
			s.assumedRecv = i
			continue
		}
		return
	}
}

func (s *Sender) rationalizeStates() {
	known := s.sent[0].S
	s.current.Subtract(known)
	for _, st := range s.sent {
		st.S.Subtract(known)
	}
}

func (s *Sender) calculateTimers() {
	now := time.Now()
	s.updateAssumedReceiverState()
	s.rationalizeStates()

	if s.pendingDataAck && s.nextAckTime.After(now.Add(ackDelay)) {
		s.nextAckTime = now.Add(ackDelay)
	}
	back := s.sent[len(s.sent)-1]
	switch {
	case !s.current.Equal(back.S):
		if !s.hasMindelay {
			s.mindelay = now
			s.hasMindelay = true
		}
		a := s.mindelay.Add(s.sendMinDelay)
		b := back.Timestamp.Add(s.SendInterval())
		s.nextSendTime = laterOf(a, b)
	case !s.current.Equal(s.sent[s.assumedRecv].S) && s.lastHeard.Add(activeRetryTimeout).After(now):
		s.nextSendTime = back.Timestamp.Add(s.SendInterval())
		if s.hasMindelay {
			s.nextSendTime = laterOf(s.nextSendTime, s.mindelay.Add(s.sendMinDelay))
		}
	case !s.current.Equal(s.sent[0].S) && s.lastHeard.Add(activeRetryTimeout).After(now):
		s.nextSendTime = back.Timestamp.Add(s.conn.Timeout()).Add(ackDelay)
	default:
		s.nextSendTime = time.Time{}
	}
	if s.shutdownInProgress || s.ackNum == noNum {
		s.nextAckTime = back.Timestamp.Add(s.SendInterval())
	}
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Tick performs whatever the timers say is due.  The caller loops on
// WaitTime/Tick.
func (s *Sender) Tick() error {
	s.calculateTimers()
	if !s.conn.HasRemoteAddr() {
		return nil
	}
	now := time.Now()
	ackDue := !now.Before(s.nextAckTime)
	sendDue := !s.nextSendTime.IsZero() && !now.Before(s.nextSendTime)
	if !ackDue && !sendDue {
		return nil
	}
	diff := s.current.DiffFrom(s.sent[s.assumedRecv].S)
	s.attemptProspectiveResend(&diff)
	if len(diff) == 0 {
		if ackDue {
			if err := s.sendEmptyAck(); err != nil {
				return err
			}
			s.hasMindelay = false
		}
		if sendDue {
			s.nextSendTime = time.Time{}
			s.hasMindelay = false
		}
		return nil
	}
	if sendDue || ackDue {
		if err := s.sendToReceiver(diff); err != nil {
			return err
		}
		s.hasMindelay = false
	}
	return nil
}

// attemptProspectiveResend lets the sender cheaply re-send from the oldest
// known state instead of the assumed one when that costs almost nothing, so a
// lost packet does not force the client to wait for a retransmit cycle.
func (s *Sender) attemptProspectiveResend(diff *[]byte) {
	if s.assumedRecv == 0 {
		return
	}
	resend := s.current.DiffFrom(s.sent[0].S)
	if len(resend) <= len(*diff) ||
		(len(resend) < 1000 && len(resend)-len(*diff) < 100) {
		s.assumedRecv = 0
		*diff = resend
	}
}

func (s *Sender) addSentState(ts time.Time, num uint64, st State) {
	s.sent = append(s.sent, &TimestampedState{Timestamp: ts, Num: num, S: st.Clone()})
	if len(s.sent) > maxSentStates {
		// Drop one entry near the newest end, as the reference
		// implementation does, keeping both the fully acknowledged front and
		// the recent tail.
		idx := len(s.sent) - 16
		if idx <= 0 {
			idx = 1
		}
		s.sent = append(s.sent[:idx], s.sent[idx+1:]...)
		if s.assumedRecv >= len(s.sent) {
			s.assumedRecv = len(s.sent) - 1
		} else if s.assumedRecv > idx {
			s.assumedRecv--
		}
	}
}

func (s *Sender) sendEmptyAck() error {
	now := time.Now()
	if !now.Before(s.nextAckTime) {
		// no-op guard kept for clarity; callers have already checked
	}
	newNum := s.sent[len(s.sent)-1].Num + 1
	if s.shutdownInProgress {
		newNum = noNum
	}
	s.addSentState(now, newNum, s.current)
	if err := s.sendFragments(nil, newNum); err != nil {
		return err
	}
	if s.shutdownInProgress {
		// Retry the shutdown instruction every quarter second.  The keepalive
		// interval is far too slow to finish a shutdown the user is waiting on,
		// while the frame rate turns the retry loop into a packet firehose for
		// something that only needs to survive a dropped datagram or two.
		s.nextAckTime = now.Add(shutdownRetry)
	} else {
		s.nextAckTime = now.Add(ackInterval)
	}
	s.nextSendTime = time.Time{}
	return nil
}

func (s *Sender) sendToReceiver(diff []byte) error {
	var newNum uint64
	back := s.sent[len(s.sent)-1]
	if s.current.Equal(back.S) {
		newNum = back.Num
	} else {
		newNum = back.Num + 1
	}
	if s.shutdownInProgress {
		newNum = noNum
	}
	now := time.Now()
	if newNum == back.Num {
		back.Timestamp = now
	} else {
		s.addSentState(now, newNum, s.current)
	}
	if err := s.sendFragments(diff, newNum); err != nil {
		return err
	}
	s.assumedRecv = len(s.sent) - 1
	s.nextAckTime = now.Add(ackInterval)
	s.nextSendTime = time.Time{}
	return nil
}

func makeChaff() []byte {
	buf := make([]byte, chaffMax+1)
	if _, err := rand.Read(buf); err != nil {
		return nil
	}
	n := int(buf[0]) % (chaffMax + 1)
	return buf[1 : 1+n]
}

func (s *Sender) sendFragments(diff []byte, newNum uint64) error {
	if s.assumedRecv >= len(s.sent) {
		s.assumedRecv = len(s.sent) - 1
	}
	inst := &ssp.Instruction{
		ProtocolVersion: ssp.ProtocolVersion,
		HasProtocol:     true,
		OldNum:          s.sent[s.assumedRecv].Num,
		HasOldNum:       true,
		NewNum:          newNum,
		HasNewNum:       true,
		AckNum:          s.ackNum,
		HasAckNum:       true,
		ThrowawayNum:    s.sent[0].Num,
		HasThrowaway:    true,
		Diff:            diff,
		HasDiff:         true,
		Chaff:           makeChaff(),
		HasChaff:        true,
	}
	if newNum == noNum {
		s.shutdownTries++
	}
	fragments, err := s.fragmenter.Make(inst, s.conn.PayloadMTU())
	if err != nil {
		return err
	}
	for _, f := range fragments {
		if err := s.conn.Send(f); err != nil {
			return err
		}
	}
	s.pendingDataAck = false
	return nil
}

// ProcessAcknowledgmentThrough discards states the receiver has confirmed.
func (s *Sender) ProcessAcknowledgmentThrough(ackNum uint64) {
	idx := -1
	for i, st := range s.sent {
		if st.Num == ackNum {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	drop := 0
	for i, st := range s.sent {
		if st.Num >= ackNum {
			drop = i
			break
		}
	}
	if drop > 0 {
		s.sent = s.sent[drop:]
		s.assumedRecv -= drop
		if s.assumedRecv < 0 {
			s.assumedRecv = 0
		}
		if s.assumedRecv >= len(s.sent) {
			s.assumedRecv = len(s.sent) - 1
		}
	}
	if len(s.sent) == 0 {
		// Should be unreachable: the acknowledged state itself is kept.
		s.sent = []*TimestampedState{{Timestamp: time.Now(), Num: ackNum, S: s.current.Clone()}}
		s.assumedRecv = 0
	}
}

// ReceivedState is one link in the receiver's chain of terminal states.  Only
// the states that are actually needed get a materialized copy; older links
// keep just the diff, which bounds memory on a lossy link.
type ReceivedState struct {
	Timestamp time.Time
	Num       uint64
	Parent    *ReceivedState
	Diff      []byte
	S         State // nil until materialized
}

// Materialize returns a live copy of this state.
func (r *ReceivedState) Materialize() (State, error) {
	if r.S != nil {
		return r.S.Clone(), nil
	}
	// Walk back to the nearest materialized ancestor.
	var chain []*ReceivedState
	cur := r
	for cur != nil && cur.S == nil {
		chain = append(chain, cur)
		cur = cur.Parent
	}
	if cur == nil {
		return nil, errors.New("transport: no materialized ancestor for state")
	}
	out := cur.S.Clone()
	for i := len(chain) - 1; i >= 0; i-- {
		if len(chain[i].Diff) > 0 {
			if err := out.ApplyString(chain[i].Diff); err != nil {
				return nil, fmt.Errorf("transport: apply diff for state %d: %w", chain[i].Num, err)
			}
		}
	}
	r.S = out
	return out.Clone(), nil
}

// Receiver implements the receiving half: it tracks the peer's versioned
// states and answers with acknowledgments.
type Receiver struct {
	states    []*ReceivedState
	byNum     map[uint64]*ReceivedState
	quench    time.Time
	diffBytes int
	// lastDelivered is the state most recently handed to the local
	// application; diffs for the sender are computed against it.
	lastDelivered State
}

// NewReceiver returns a receiver primed with the peer's initial state.
func NewReceiver(initial State) *Receiver {
	r0 := &ReceivedState{Timestamp: time.Now(), Num: 0, S: initial.Clone()}
	return &Receiver{
		states:        []*ReceivedState{r0},
		byNum:         map[uint64]*ReceivedState{0: r0},
		lastDelivered: initial.Clone(),
	}
}

// Latest returns the newest state the peer has delivered.
func (r *Receiver) Latest() (*ReceivedState, error) {
	if len(r.states) == 0 {
		return nil, errors.New("transport: no received states")
	}
	return r.states[len(r.states)-1], nil
}

// LatestNum returns the newest received state number, or 0.
func (r *Receiver) LatestNum() uint64 {
	if len(r.states) == 0 {
		return 0
	}
	return r.states[len(r.states)-1].Num
}

// ProcessInstruction validates and applies one instruction's diff against the
// state it claims to build on, and reports whether new state was accepted.
func (r *Receiver) ProcessInstruction(inst *ssp.Instruction) (bool, error) {
	if !inst.HasProtocol || inst.ProtocolVersion != ssp.ProtocolVersion {
		return false, fmt.Errorf("%w: protocol version %d", ErrProtocol, inst.ProtocolVersion)
	}
	if !inst.HasNewNum || !inst.HasOldNum {
		return false, fmt.Errorf("%w: instruction missing state numbers", ErrProtocol)
	}
	if _, dup := r.byNum[inst.NewNum]; dup {
		return false, nil // already have this state
	}
	ref, ok := r.byNum[inst.OldNum]
	if !ok {
		// The reference state was discarded or has not arrived yet.  Ignoring
		// it is deliberate and security-relevant: it is how idempotency and
		// replay resistance are enforced.
		return false, nil
	}
	r.processThrowawayUntil(inst.ThrowawayNum)

	if len(r.states) >= maxReceivedStates || r.diffBytes > maxReceiverDiffBytes ||
		len(inst.Diff) > maxReceiverDiffBytes-r.diffBytes {
		now := time.Now()
		if !now.Before(r.quench) {
			r.quench = now.Add(receiverQuenchPause)
		}
		return false, nil // drop rather than let the queue grow
	}
	newState := &ReceivedState{Timestamp: time.Now(), Num: inst.NewNum, Parent: ref, Diff: inst.Diff}
	if len(inst.Diff) > 0 {
		// Materialize the reference, apply the diff, and keep it: this is the
		// newest state, so it will be needed for rendering immediately.
		base, err := ref.Materialize()
		if err != nil {
			return false, err
		}
		if err := base.ApplyString(inst.Diff); err != nil {
			return false, err
		}
		newState.S = base
	}
	r.insertSorted(newState)
	r.trim()
	return true, nil
}

func (r *Receiver) insertSorted(s *ReceivedState) {
	pos := sort.Search(len(r.states), func(i int) bool { return r.states[i].Num > s.Num })
	r.states = append(r.states, nil)
	copy(r.states[pos+1:], r.states[pos:])
	r.states[pos] = s
	if r.byNum == nil {
		r.byNum = map[uint64]*ReceivedState{}
	}
	r.byNum[s.Num] = s
	r.diffBytes += len(s.Diff)
}

func (r *Receiver) processThrowawayUntil(throwaway uint64) {
	var last *ReceivedState
	if len(r.states) > 0 {
		last = r.states[len(r.states)-1]
	}
	kept := r.states[:0]
	for _, s := range r.states {
		if s.Num < throwaway && s != last {
			delete(r.byNum, s.Num)
			r.diffBytes -= len(s.Diff)
			continue
		}
		kept = append(kept, s)
	}
	r.states = kept
	if len(r.states) == 0 {
		// Never empty the queue: the newest state is always usable.
		if last != nil {
			r.states = []*ReceivedState{last}
			r.byNum[last.Num] = last
		}
	}
}

// trim unmaterializes interior states so memory stays bounded.  The oldest
// kept state stays materialized: it is the anchor every other state is
// rebuilt from, and diffs are never discarded, so a state can always be
// reconstructed exactly.
func (r *Receiver) trim() {
	if len(r.states) <= materializedCache+1 {
		return
	}
	for i := 1; i < len(r.states)-materializedCache; i++ {
		r.states[i].S = nil
	}
}

// Deliver returns the newest materialized state and records it as delivered,
// mirroring how the reference client renders from latest_remote_state.
func (r *Receiver) Deliver() (State, uint64, error) {
	latest, err := r.Latest()
	if err != nil {
		return nil, 0, err
	}
	s, err := latest.Materialize()
	if err != nil {
		return nil, 0, err
	}
	r.lastDelivered = s
	return s, latest.Num, nil
}
