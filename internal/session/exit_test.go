package session_test

import (
	"strings"
	"testing"
	"time"

	"winsh/internal/session"
)

// TestExitCompletes covers the Ctrl-^ . quit path.  It used to print
// "Exiting on user request..." and then sit there: the shutdown instruction was
// re-offered at the keepalive interval instead of the frame rate, and Stop()
// waited indefinitely on a console reader parked in ReadConsoleInputW.
func TestExitCompletes(t *testing.T) {
	cl, _, _, cleanup := mkSession(t)
	defer cleanup()

	cl.PushInput([]byte("warmup\r"))
	waitFor(t, "warm-up echo", func() bool {
		return strings.Contains(screenText(t, cl), "warmup")
	})

	// Ctrl-^ (30) arms wherever the cursor is, so no Enter is needed first;
	// pushing one here used to mask the bug that made the escape dead mid-line.
	cl.PushInput([]byte{0x1E, '.'})

	stopped := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			if !cl.Running() {
				close(stopped)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	select {
	case <-stopped:
	case <-time.After(8 * time.Second):
		t.Fatal("session did not end after the quit command: exit is hanging")
	}
}

// TestResizeFollowsTheWindow checks that a size change reaches the server,
// which is what pollSize exists to guarantee even when Windows sends no
// WINDOW_BUFFER_SIZE_EVENT.
func TestResizeFollowsTheWindow(t *testing.T) {
	cl, srv, _, cleanup := mkSession(t)
	defer cleanup()

	waitFor(t, "initial size exchange", func() bool { return srv.LastSentNum() > 0 })

	cl.PushResize(132, 43)
	waitFor(t, "the resize to be sent", func() bool {
		return strings.Contains(screenText(t, cl), "132") || srv.LastSentNum() > 1
	})
	if got := cl.LastRendered(); got == nil {
		t.Fatal("no screen after resize")
	}
	_ = session.PredictNever
}
