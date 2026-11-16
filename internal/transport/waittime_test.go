package transport

import (
	"testing"
	"time"

	"winsh/internal/moshcrypto"
)

// The event loop decides how long to block by asking the sender when it next
// has to run.  When that answer was ambiguous the whole client ran at 1 Hz
// instead of mosh's 20-250 ms frame rate, and nothing failed loudly enough for
// anyone to notice: everything still arrived, eventually.  These pin the
// three-valued contract directly: -1 idle, 0 due now, >0 sleep at most this long.

func TestWaitTimeFromIdleIsNotDueNow(t *testing.T) {
	if got := waitTimeFrom(time.Time{}, time.Time{}); got != -1 {
		t.Errorf("no timers set: got %v, want -1 (idle)", got)
	}
}

func TestWaitTimeFromSkipsUnsetTimers(t *testing.T) {
	future := time.Now().Add(600 * time.Millisecond)
	// An unset timer is the zero time.  Comparing it rather than skipping it
	// makes time.Until hugely negative, which reads as "due now" on every pass
	// and turns the loop into a busy spin.
	if got := waitTimeFrom(future, time.Time{}); got <= 0 || got > 600*time.Millisecond {
		t.Errorf("only ack scheduled: got %v, want the ack duration in (0,600ms]", got)
	}
	if got := waitTimeFrom(time.Time{}, future); got <= 0 || got > 600*time.Millisecond {
		t.Errorf("only send scheduled: got %v, want the send duration in (0,600ms]", got)
	}
}

func TestWaitTimeFromPicksTheEarlierTimer(t *testing.T) {
	late := time.Now().Add(900 * time.Millisecond)
	soon := time.Now().Add(30 * time.Millisecond)
	if got := waitTimeFrom(late, soon); got > 100*time.Millisecond {
		t.Errorf("got %v, want the 30ms send timer to win", got)
	}
	if got := waitTimeFrom(soon, late); got > 100*time.Millisecond {
		t.Errorf("got %v, want the 30ms ack timer to win", got)
	}
}

func TestWaitTimeFromExpiredTimerMeansRunNow(t *testing.T) {
	past := time.Now().Add(-time.Second)
	if got := waitTimeFrom(past, time.Time{}); got != 0 {
		t.Errorf("expired timer: got %v, want 0 (do not sleep, run Tick again)", got)
	}
	// 0 must stay distinguishable from -1, which is exactly the collapse that
	// caused the stall.
	if waitTimeFrom(past, time.Time{}) == waitTimeFrom(time.Time{}, time.Time{}) {
		t.Error("due-now and idle must not share a return value")
	}
}

func TestMergeWaitTreatsNegativeExtraAsNoHint(t *testing.T) {
	if got := mergeWait(500*time.Millisecond, -1); got != 500*time.Millisecond {
		t.Errorf("no-hint merged to %v; 0 used to mean both 'no hint' and 'wake now'", got)
	}
	if got := mergeWait(500*time.Millisecond, 5*time.Millisecond); got != 5*time.Millisecond {
		t.Errorf("an earlier hint was ignored: %v", got)
	}
	if got := mergeWait(5*time.Millisecond, 500*time.Millisecond); got != 5*time.Millisecond {
		t.Errorf("a later hint overrode an earlier schedule: %v", got)
	}
	// Sentinels survive the merge.
	if got := mergeWait(-1, -1); got != -1 {
		t.Errorf("idle: got %v, want -1", got)
	}
	if got := mergeWait(0, -1); got != 0 {
		t.Errorf("due now: got %v, want 0", got)
	}
	// An idle sender must not be pinned busy by a hint that says "now".
	if got := mergeWait(-1, 0); got != 0 {
		t.Errorf("idle with a now-hint: got %v, want 0", got)
	}
}

func TestSenderWaitTimeWithoutRemoteAddressIsIdle(t *testing.T) {
	key, err := moshcrypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewClientConnection(key, nil, ConnOptions{BindIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("NewClientConnection: %v", err)
	}
	defer conn.Close()
	s := NewSender(conn, &listState{})
	if got := s.WaitTime(); got != -1 {
		t.Errorf("WaitTime with no peer address = %v, want -1", got)
	}
}
