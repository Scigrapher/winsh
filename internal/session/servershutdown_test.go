package session_test

import (
	"testing"
	"time"
)

// TestSessionEndsWhenTheServerShutsDown is the "typing exit at a shell prompt
// hangs forever" test.  When the user's shell exits, mosh-server starts its own
// graceful shutdown (mosh-server.cc calls start_shutdown when the child's pty
// reaches EOF) and every instruction it sends from then on carries
// new_num = 2^64-1.  The client has to acknowledge that state -- by putting
// 2^64-1 in the ack_num of an instruction it sends -- and then return, which is
// precisely mosh's counterparty_shutdown_ack_sent test in stmclient.cc.  A client
// that only ever reacts to its own shutdown leaves the terminal attached to a
// dead session until the user kills it.
func TestSessionEndsWhenTheServerShutsDown(t *testing.T) {
	r := newRig(t, false)
	r.warmUp(t)

	r.srv.StartShutdown()
	select {
	case err := <-r.runErr:
		if err != nil {
			t.Fatalf("Run returned %v after the server shut down; a server-initiated exit is not an error", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("the session never ended although the server shut down")
	}
	if !r.cl.CleanExit() {
		t.Error("CleanExit() is false after a server-initiated shutdown")
	}
}
