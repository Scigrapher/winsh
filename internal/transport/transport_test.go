package transport

import (
	"bytes"
	"compress/zlib"
	"net"
	"strings"
	"testing"
	"time"

	"winsh/internal/moshcrypto"
	"winsh/internal/ssp"
)

// listState is a minimal State used to exercise the transport machinery
// without dragging in the terminal emulator.
type listState struct{ events []byte }

func (s *listState) Clone() State {
	c := &listState{events: make([]byte, len(s.events))}
	copy(c.events, s.events)
	return c
}

func (s *listState) DiffFrom(existing State) []byte {
	e, ok := existing.(*listState)
	if !ok || len(e.events) > len(s.events) {
		return nil
	}
	for i, b := range e.events {
		if s.events[i] != b {
			return nil // not a prefix: no safe diff exists
		}
	}
	out := make([]byte, len(s.events)-len(e.events))
	copy(out, s.events[len(e.events):])
	return out
}

func (s *listState) InitDiff() []byte { return s.DiffFrom(&listState{}) }

func (s *listState) ApplyString(diff []byte) error {
	s.events = append(s.events, diff...)
	return nil
}

func (s *listState) Subtract(prefix State) {
	e, ok := prefix.(*listState)
	if !ok || len(e.events) > len(s.events) {
		return
	}
	for i, b := range e.events {
		if s.events[i] != b {
			return
		}
	}
	s.events = s.events[len(e.events):]
}

func (s *listState) Equal(o State) bool {
	other, ok := o.(*listState)
	return ok && bytes.Equal(s.events, other.events)
}

func mustKey(t *testing.T) moshcrypto.Key {
	t.Helper()
	k, err := moshcrypto.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func TestFragmentRoundTrip(t *testing.T) {
	key := mustKey(t)
	_ = key
	var fr Fragmenter
	// Incompressible payload, so fragmentation actually happens.
	big := make([]byte, 3600)
	for i := range big {
		big[i] = byte(i*1103515245/16 + i>>3)
	}
	inst := &ssp.Instruction{
		ProtocolVersion: ssp.ProtocolVersion, HasProtocol: true,
		OldNum: 0, HasOldNum: true, NewNum: 1, HasNewNum: true,
		AckNum: 0, HasAckNum: true, ThrowawayNum: 0, HasThrowaway: true,
		Diff: big, HasDiff: true, Chaff: []byte("chaff"), HasChaff: true,
	}
	parts, err := fr.Make(inst, 200)
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	if len(parts) < 3 {
		t.Fatalf("expected several fragments, got %d", len(parts))
	}
	var asm Assembly
	// Feed out of order and duplicate the first fragment.
	order := make([]int, len(parts))
	for i := range order {
		order[i] = i
	}
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	var done bool
	for _, idx := range order {
		f, err := ParseFragment(parts[idx])
		if err != nil {
			t.Fatalf("ParseFragment: %v", err)
		}
		done, err = asm.Add(f)
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if !done {
		t.Fatalf("assembly did not complete")
	}
	f0, _ := ParseFragment(parts[0])
	if _, err := asm.Add(f0); err != nil {
		t.Fatalf("duplicate fragment rejected: %v", err)
	}
}

func TestAssemblyRejectsConflictingRetransmission(t *testing.T) {
	var asm Assembly
	a := &Fragment{ID: 7, Num: 0, Final: true, Contents: []byte("aaaa")}
	b := &Fragment{ID: 7, Num: 0, Final: true, Contents: []byte("bbbb")}
	if _, err := asm.Add(a); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if _, err := asm.Add(b); err == nil {
		t.Fatalf("expected conflicting retransmission to be rejected")
	}
}

func TestInflateRejectsBomb(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	for i := 0; i < 200000; i++ {
		if _, err := w.Write([]byte("0000000000000000")); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	if _, err := Inflate(buf.Bytes(), 4096); err == nil {
		t.Fatalf("expected oversized expansion to be rejected")
	}
}

func TestReceiverIgnoresUnknownReference(t *testing.T) {
	r := NewReceiver(&listState{})
	inst := &ssp.Instruction{
		ProtocolVersion: ssp.ProtocolVersion, HasProtocol: true,
		OldNum: 42, HasOldNum: true, NewNum: 43, HasNewNum: true,
		Diff: []byte("hi"), HasDiff: true,
	}
	ok, err := r.ProcessInstruction(inst)
	if err != nil {
		t.Fatalf("ProcessInstruction: %v", err)
	}
	if ok {
		t.Fatalf("state with an unknown reference must be ignored")
	}
	// And it must not have been recorded as known.
	if _, dup := r.byNum[43]; dup {
		t.Fatalf("ignored state was still registered")
	}
}

func TestReceiverAppliesOutOfOrderChain(t *testing.T) {
	r := NewReceiver(&listState{})
	mk := func(old, new uint64, diff string) *ssp.Instruction {
		return &ssp.Instruction{
			ProtocolVersion: ssp.ProtocolVersion, HasProtocol: true,
			OldNum: old, HasOldNum: true, NewNum: new, HasNewNum: true,
			Diff: []byte(diff), HasDiff: true,
		}
	}
	if ok, err := r.ProcessInstruction(mk(0, 1, "a")); err != nil || !ok {
		t.Fatalf("state 1: ok=%v err=%v", ok, err)
	}
	// 3 depends on 2, which we do not have yet.
	if ok, _ := r.ProcessInstruction(mk(2, 3, "c")); ok {
		t.Fatalf("state 3 must wait for its reference")
	}
	if ok, _ := r.ProcessInstruction(mk(1, 2, "b")); !ok {
		t.Fatalf("state 2 should apply")
	}
	// Now 3 is applicable, but its reference (2) is known: apply directly.
	if ok, _ := r.ProcessInstruction(mk(2, 3, "c")); !ok {
		t.Fatalf("state 3 should now apply")
	}
	got, num, err := r.Deliver()
	if err != nil {
		t.Fatal(err)
	}
	if num != 3 {
		t.Fatalf("latest num = %d, want 3", num)
	}
	if string(got.(*listState).events) != "abc" {
		t.Fatalf("events = %q, want abc", got.(*listState).events)
	}
}

func TestAssemblyCopiesDiffOutOfInflatedBuffer(t *testing.T) {
	// A tiny diff travelling with a large chaff field used to leave Diff
	// pointing into the whole inflated instruction, so every retained state
	// pinned several megabytes even though diffBytes counted a few bytes.
	chaff := make([]byte, 3000)
	for i := range chaff {
		chaff[i] = byte(i)
	}
	inst := &ssp.Instruction{
		ProtocolVersion: ssp.ProtocolVersion, HasProtocol: true,
		OldNum: 0, HasOldNum: true, NewNum: 1, HasNewNum: true,
		Diff: []byte("small diff"), HasDiff: true,
		Chaff: chaff, HasChaff: true,
	}
	var fr Fragmenter
	parts, err := fr.Make(inst, 200)
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	var asm Assembly
	for _, part := range parts {
		f, err := ParseFragment(part)
		if err != nil {
			t.Fatalf("ParseFragment: %v", err)
		}
		if _, err := asm.Add(f); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	got, err := asm.Instruction()
	if err != nil {
		t.Fatalf("Instruction: %v", err)
	}
	if string(got.Diff) != "small diff" {
		t.Fatalf("diff = %q", got.Diff)
	}
	// Go rounds a 10-byte allocation up to a 16-byte size class; what matters
	// is that the backing array is not the multi-kilobyte inflated buffer.
	if cap(got.Diff) >= 1024 {
		t.Fatalf("diff capacity %d for a %d-byte diff; it still pins the inflated buffer", cap(got.Diff), len(got.Diff))
	}
}

func TestReceiverPrunesDroppedHistory(t *testing.T) {
	r := NewReceiver(&listState{})
	for i := 1; i <= 5000; i++ {
		inst := testInstruction(uint64(i-1), uint64(i), []byte{byte(i)})
		inst.ThrowawayNum = uint64(i - 1)
		inst.HasThrowaway = true
		ok, err := r.ProcessInstruction(inst)
		if err != nil || !ok {
			t.Fatalf("state %d: ok=%v err=%v", i, ok, err)
		}
	}
	if len(r.states) > 3 {
		t.Fatalf("retained %d states after throwaway, want a small window", len(r.states))
	}
	if len(r.byNum) != len(r.states) {
		t.Fatalf("lookup map holds %d states, list holds %d", len(r.byNum), len(r.states))
	}
	// Walking the retained ancestry must terminate in the current window.  A
	// pointer chain used to remain 5000 links deep.
	cur := r.states[len(r.states)-1]
	depth := 0
	for cur.HasParent {
		next, ok := r.byNum[cur.ParentNum]
		if !ok {
			t.Fatalf("retained state %d points at dropped parent %d", cur.Num, cur.ParentNum)
		}
		cur = next
		depth++
		if depth > 4 {
			t.Fatalf("ancestry depth %d is not bounded", depth)
		}
	}
}

func TestReceiverBoundsMaterializedSnapshots(t *testing.T) {
	r := NewReceiver(&listState{})
	for i := 1; i <= 200; i++ {
		if ok, err := r.ProcessInstruction(testInstruction(uint64(i-1), uint64(i), []byte{byte(i)})); err != nil || !ok {
			t.Fatalf("state %d: ok=%v err=%v", i, ok, err)
		}
	}
	materialized := 0
	for _, s := range r.states {
		if s.S != nil {
			materialized++
		}
	}
	if materialized > materializedCache+1 {
		t.Fatalf("%d materialized snapshots retained, limit is %d", materialized, materializedCache+1)
	}
}

func TestReceiverBuildsOnReferenceRetiredByThrowaway(t *testing.T) {
	r := NewReceiver(&listState{})
	for i := 1; i <= 3; i++ {
		if ok, err := r.ProcessInstruction(testInstruction(uint64(i-1), uint64(i), []byte("abc"[i-1:i]))); err != nil || !ok {
			t.Fatalf("state %d: ok=%v err=%v", i, ok, err)
		}
	}
	// State 4 builds on state 1 even though the same instruction asks the
	// receiver to retire everything older than itself.  The reference has to
	// be snapshotted before throwaway clears it.
	inst := testInstruction(1, 4, []byte("d"))
	inst.ThrowawayNum = 4
	inst.HasThrowaway = true
	if ok, err := r.ProcessInstruction(inst); err != nil || !ok {
		t.Fatalf("state 4: ok=%v err=%v", ok, err)
	}
	got, num, err := r.Deliver()
	if err != nil {
		t.Fatal(err)
	}
	if num != 4 || string(got.(*listState).events) != "ad" {
		t.Fatalf("delivered %d %q, want 4 %q", num, got.(*listState).events, "ad")
	}
}

// pair builds a client and a server-shaped connection over loopback sharing
// one session key, as a real mosh session does.
func pair(t *testing.T) (client, server *Connection, key moshcrypto.Key) {
	t.Helper()
	key = mustKey(t)
	lo := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	server, err := NewClientConnection(key, lo, ConnOptions{
		BindIP:             "127.0.0.1",
		SendDirection:      ToClient,
		ExpectDirection:    ToServer,
		ExpectDirectionSet: true,
	})
	if err != nil {
		t.Fatalf("server conn: %v", err)
	}
	client, err = NewClientConnection(key, server.LocalAddr(), ConnOptions{BindIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	server.SetRemote(client.LocalAddr())
	return client, server, key
}

// drive pumps both transports until they settle or the budget runs out.
func drive(t *testing.T, c, s *Transport, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if _, err := c.Poll(time.Now().Add(2 * time.Millisecond)); err != nil {
			t.Fatalf("client poll: %v", err)
		}
		if err := c.Tick(); err != nil {
			t.Fatalf("client tick: %v", err)
		}
		if _, err := s.Poll(time.Now().Add(2 * time.Millisecond)); err != nil {
			t.Fatalf("server poll: %v", err)
		}
		if err := s.Tick(); err != nil {
			t.Fatalf("server tick: %v", err)
		}
	}
}

func TestTransportConvergesOverLoopback(t *testing.T) {
	cc, sc, _ := pair(t)
	defer cc.Close()
	defer sc.Close()
	client := NewTransport(cc, &listState{}, &listState{})
	server := NewTransport(sc, &listState{}, &listState{})

	want := []byte("the quick brown fox jumps over the lazy dog")
	client.Sender.Push(func(st State) { st.(*listState).events = append(st.(*listState).events, want...) })

	drive(t, client, server, 2*time.Second)

	got, num, err := server.Receiver.Deliver()
	if err != nil {
		t.Fatal(err)
	}
	if string(got.(*listState).events) != string(want) {
		t.Fatalf("server received %q (state %d), want %q", got.(*listState).events, num, want)
	}
	if client.Sender.SentStateAcked() == 0 {
		t.Fatalf("client never got an acknowledgment")
	}
}

func TestRedialRebindsToFreshLocalPort(t *testing.T) {
	cc, sc, _ := pair(t)
	defer cc.Close()
	defer sc.Close()

	prev := cc.LocalAddr()
	if prev == nil {
		t.Fatal("client has no initial local address")
	}
	for i := 0; i < 10; i++ {
		if err := cc.Redial(); err != nil {
			t.Fatalf("redial %d: %v", i, err)
		}
		cur := cc.LocalAddr()
		if cur == nil {
			t.Fatalf("redial %d left the connection without a local address", i)
		}
		if cur.Port == prev.Port {
			t.Fatalf("redial %d reused local port %d", i, cur.Port)
		}
		prev = cur
	}
}

func TestTransportRecoversFromDroppedPackets(t *testing.T) {
	cc, sc, _ := pair(t)
	defer cc.Close()
	defer sc.Close()
	// Drop every other outgoing datagram from both sides.
	var n uint64
	cc.dropFn = func([]byte) bool { n++; return n%2 == 0 }
	var m uint64
	sc.dropFn = func([]byte) bool { m++; return m%3 == 0 }

	client := NewTransport(cc, &listState{}, &listState{})
	server := NewTransport(sc, &listState{}, &listState{})

	// Push in chunks so that several states and retransmissions are involved.
	chunks := []string{"alpha", "bravo", "charlie", "delta ", "echo-5"}
	for _, ch := range chunks {
		s := ch
		client.Sender.Push(func(st State) { st.(*listState).events = append(st.(*listState).events, s...) })
		drive(t, client, server, 300*time.Millisecond)
	}
	drive(t, client, server, 3*time.Second)

	got, _, err := server.Receiver.Deliver()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join(chunks, "")
	if string(got.(*listState).events) != "alphabravocharliedelta echo-5" {
		t.Fatalf("server received %q, want %q (sent %d dropped %d)", got.(*listState).events, want, n, m)
	}
}
