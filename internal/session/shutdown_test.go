package session_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"winsh/internal/fakeserver"
	"winsh/internal/moshcrypto"
	"winsh/internal/session"
	"winsh/internal/state"
	"winsh/internal/transport"
	"winsh/internal/vt"
)

// rig is a client wired to the fake server with the pieces a shutdown test
// needs to reach for: the Run result, and a switch that stops the server
// answering so it can be made to "die".
type rig struct {
	cl       *session.Client
	srv      *fakeserver.Server
	conn     *transport.Connection
	runErr   chan error
	stopPump chan struct{}
	killOnce sync.Once
}

func newRig(t *testing.T, haveCommand bool) *rig {
	t.Helper()
	key, err := moshcrypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := fakeserver.New(key, lo(0), fakeserver.Options{Cols: 80, Rows: 24, Echo: true})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.NewClientConnection(key, lo(srv.Port()), transport.ConnOptions{BindIP: "127.0.0.1"})
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	srv.Attach(conn.LocalAddr())
	tr := transport.NewTransport(conn, &state.UserStream{}, vt.NewTerminalState(80, 24))
	tr.Sender.SetSendDelay(time.Millisecond)
	cl := session.New(nil, tr, 80, 24, session.Options{
		Predict:           session.PredictNever,
		NoTermInit:        true,
		ServerHost:        "127.0.0.1",
		ServerPort:        srv.Port(),
		HaveRemoteCommand: haveCommand,
	})
	r := &rig{cl: cl, srv: srv, conn: conn, runErr: make(chan error, 1), stopPump: make(chan struct{})}
	go func() {
		for {
			select {
			case <-r.stopPump:
				return
			default:
			}
			if _, err := srv.ServeOnce(time.Now().Add(2 * time.Millisecond)); err != nil {
				return
			}
		}
	}()
	go func() { r.runErr <- cl.Run() }()
	t.Cleanup(func() {
		r.killServer()
		cl.Stop()
		conn.Close()
		srv.Close()
	})
	return r
}

// killServer stops the fake server answering, which is how these tests simulate
// mosh-server exiting when the remote command finishes.  Guarded because
// Cleanup and the test body both reach for it.
func (r *rig) killServer() {
	r.killOnce.Do(func() { close(r.stopPump) })
}

func (r *rig) await(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (r *rig) warmUp(t *testing.T) {
	t.Helper()
	r.cl.PushInput([]byte("warmup\r"))
	r.await(t, "warm-up echo", func() bool {
		return strings.Contains(screenText(t, r.cl), "warmup")
	})
}

// TestUserQuitIsAcknowledged covers Ctrl-^ . against a live server.  Besides
// ending at all -- the original bug was that it never did -- it must end
// *acknowledged* and quickly; falling through to the pass-count fallback would
// mean the shutdown handshake itself had regressed.
func TestUserQuitIsAcknowledged(t *testing.T) {
	r := newRig(t, false)
	r.warmUp(t)

	start := time.Now()
	// No newline first: a control escape arms mid-line, exactly as a user
	// reaching for Ctrl-^ after typing a command line would expect.
	r.cl.PushInput([]byte{0x1E, '.'})

	select {
	case err := <-r.runErr:
		if err != nil {
			t.Fatalf("Run returned an error on a user-requested quit: %v", err)
		}
		if d := time.Since(start); d > 1500*time.Millisecond {
			t.Errorf("quit took %v; a live server should acknowledge the shutdown promptly", d)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("the session never ended after Ctrl-^ .")
	}
	if !r.cl.CleanExit() {
		t.Error("CleanExit() is false after an acknowledged quit")
	}
}

// TestRemoteCommandExitsWhenServerDies covers "winsh host command": mosh-server
// exits when the command finishes and there is no reliable goodbye, so the
// client has to infer death from silence and return.
func TestRemoteCommandExitsWhenServerDies(t *testing.T) {
	r := newRig(t, true)
	r.warmUp(t)

	// Kill the server: stop answering its acknowledgements.
	r.killServer()

	start := time.Now()
	select {
	case err := <-r.runErr:
		if err != nil {
			t.Fatalf("Run returned an error when the server died after a command: %v", err)
		}
		if d := time.Since(start); d > 6*time.Second {
			t.Errorf("took %v to notice the dead server; commandIdleExit plus the shutdown budget should be under 5s", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client never returned after the server died mid-command")
	}
	if !r.cl.CleanExit() {
		t.Error("a finished command is a clean exit, but CleanExit() is false")
	}
}

// TestInteractiveSessionSurvivesServerSilence is the counter-case: without a
// one-shot command, a quiet server must NOT end the session, or a dropped
// packet would look like a finished login shell.
func TestInteractiveSessionSurvivesServerSilence(t *testing.T) {
	r := newRig(t, false)
	r.warmUp(t)
	r.killServer()

	select {
	case err := <-r.runErr:
		t.Fatalf("an interactive session ended on server silence (err=%v); only -t/--server-timeout may do that", err)
	case <-time.After(session.CommandIdleExit + 2*time.Second):
		// still running, as intended
	}
}
