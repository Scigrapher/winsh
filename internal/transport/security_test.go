package transport

import (
	"testing"

	"winsh/internal/ssp"
)

func testInstruction(old, new uint64, diff []byte) *ssp.Instruction {
	return &ssp.Instruction{
		ProtocolVersion: ssp.ProtocolVersion, HasProtocol: true,
		OldNum: old, HasOldNum: true, NewNum: new, HasNewNum: true,
		Diff: diff, HasDiff: true,
	}
}

func TestReceiverRejectsDiffBeyondByteBudget(t *testing.T) {
	r := NewReceiver(&listState{})
	r.diffBytes = maxReceiverDiffBytes - 1
	ok, err := r.ProcessInstruction(testInstruction(0, 1, []byte("ab")))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("receiver accepted a diff that exceeded the retained-byte budget")
	}
	if len(r.states) != 1 || r.diffBytes != maxReceiverDiffBytes-1 {
		t.Fatalf("receiver state changed after rejection: states=%d bytes=%d", len(r.states), r.diffBytes)
	}
}

func TestReceiverThrowawayKeepsNewestStateAndTracksBytes(t *testing.T) {
	r := NewReceiver(&listState{})
	if ok, err := r.ProcessInstruction(testInstruction(0, 1, []byte("a"))); err != nil || !ok {
		t.Fatalf("apply state 1: ok=%v err=%v", ok, err)
	}
	if r.diffBytes != 1 {
		t.Fatalf("retained diff bytes = %d, want 1", r.diffBytes)
	}
	r.processThrowawayUntil(100)
	if len(r.states) != 1 || r.states[0].Num != 1 {
		t.Fatalf("throwaway emptied or changed the newest state: %+v", r.states)
	}
	if _, ok := r.byNum[1]; !ok {
		t.Fatal("newest state was removed from the lookup map")
	}
	if r.diffBytes != 1 {
		t.Fatalf("retained diff bytes after throwaway = %d, want 1", r.diffBytes)
	}
}
