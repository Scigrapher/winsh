package session_test

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"winsh/internal/fakeserver"
	"winsh/internal/moshcrypto"
	"winsh/internal/session"
	"winsh/internal/state"
	"winsh/internal/transport"
	"winsh/internal/vt"
)

func lo(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port} }

// runSession wires a headless client to the fake mosh server and keeps both
// event loops turning until the returned cleanup runs.
func runSession(t *testing.T, echo bool) (*session.Client, *fakeserver.Server, func()) {
	t.Helper()
	key, err := moshcrypto.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	srv, err := fakeserver.New(key, lo(0), fakeserver.Options{Cols: 80, Rows: 24, Echo: echo})
	if err != nil {
		t.Fatalf("fakeserver: %v", err)
	}
	conn, err := transport.NewClientConnection(key, lo(srv.Port()), transport.ConnOptions{BindIP: "127.0.0.1"})
	if err != nil {
		srv.Close()
		t.Fatalf("client connection: %v", err)
	}
	srv.Attach(conn.LocalAddr())
	tr := transport.NewTransport(conn, &state.UserStream{}, vt.NewTerminalState(80, 24))
	tr.Sender.SetSendDelay(time.Millisecond)

	cl := session.New(nil, tr, 80, 24, session.Options{
		Predict:    session.PredictNever,
		EscapeKey:  -1,
		NoTermInit: true,
		ServerHost: "127.0.0.1",
		ServerPort: srv.Port(),
	})

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := srv.ServeOnce(time.Now().Add(2 * time.Millisecond)); err != nil {
				return
			}
		}
	}()
	go func() { _ = cl.Run() }()

	return cl, srv, func() {
		close(stop)
		cl.Stop()
		conn.Close()
		srv.Close()
	}
}

// mkSession wires a headless client to the fake server and starts both event
// loops.  Unlike runSession it also hands back the client's Connection, so
// tests can observe the socket and counters across a re-dial.
func mkSession(t *testing.T) (*session.Client, *fakeserver.Server, *transport.Connection, func()) {
	t.Helper()
	key, err := moshcrypto.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	srv, err := fakeserver.New(key, lo(0), fakeserver.Options{Cols: 80, Rows: 24, Echo: true})
	if err != nil {
		t.Fatalf("fakeserver: %v", err)
	}
	conn, err := transport.NewClientConnection(key, lo(srv.Port()), transport.ConnOptions{BindIP: "127.0.0.1"})
	if err != nil {
		srv.Close()
		t.Fatalf("client connection: %v", err)
	}
	srv.Attach(conn.LocalAddr())
	tr := transport.NewTransport(conn, &state.UserStream{}, vt.NewTerminalState(80, 24))
	tr.Sender.SetSendDelay(time.Millisecond)
	cl := session.New(nil, tr, 80, 24, session.Options{
		Predict:    session.PredictNever,
		NoTermInit: true,
		ServerHost: "127.0.0.1",
		ServerPort: srv.Port(),
	})
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := srv.ServeOnce(time.Now().Add(2 * time.Millisecond)); err != nil {
				return
			}
		}
	}()
	go func() { _ = cl.Run() }()
	return cl, srv, conn, func() {
		close(stop)
		cl.Stop()
		conn.Close()
		srv.Close()
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
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

func screenText(t *testing.T, cl *session.Client) string {
	t.Helper()
	rows, err := cl.DumpScreen()
	if err != nil {
		return ""
	}
	return strings.Join(rows, "\n")
}

// localPort reports the connection's current local port.  LocalAddr can be
// nil when the connection has no socket, so the test tolerates that rather
// than dereferencing it.
func localPort(conn *transport.Connection) int {
	if a := conn.LocalAddr(); a != nil {
		return a.Port
	}
	return 0
}

// TestSessionEchoRoundTrip is the end-to-end test: keystrokes travel to the
// server through SSP, come back as rendered terminal output, and appear on the
// client's screen.
func TestSessionEchoRoundTrip(t *testing.T) {
	cl, _, cleanup := runSession(t, true)
	defer cleanup()

	cl.PushInput([]byte("echo hi\r"))
	waitFor(t, "server echo of typed input", func() bool {
		return strings.Contains(screenText(t, cl), "echo hi")
	})
}

func TestServerInitiatedOutputReachesClient(t *testing.T) {
	cl, srv, cleanup := runSession(t, true)
	defer cleanup()

	waitFor(t, "initial state exchange", func() bool { return srv.LastSentNum() > 0 })
	srv.Printf("the quick brown fox\r\n")
	waitFor(t, "server output on the client screen", func() bool {
		return strings.Contains(screenText(t, cl), "the quick brown fox")
	})
}

func TestPredictionEchoesLocallyBeforeServerReplies(t *testing.T) {
	key, err := moshcrypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	// A server that receives but never answers: local echo must still show
	// what the user typed, which is mosh's whole point on a slow link.
	srv, err := fakeserver.New(key, lo(0), fakeserver.Options{Cols: 80, Rows: 24, Echo: false})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, err := transport.NewClientConnection(key, lo(srv.Port()), transport.ConnOptions{BindIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	srv.Attach(conn.LocalAddr())
	tr := transport.NewTransport(conn, &state.UserStream{}, vt.NewTerminalState(80, 24))
	cl := session.New(nil, tr, 80, 24, session.Options{
		Predict:    session.PredictAlways,
		EscapeKey:  -1,
		NoTermInit: true,
	})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := srv.ServeOnce(time.Now().Add(2 * time.Millisecond)); err != nil {
				return
			}
		}
	}()
	go func() { _ = cl.Run() }()
	defer cl.Stop()

	cl.PushInput([]byte("typing"))
	waitFor(t, "predicted text on the local screen", func() bool {
		rows, err := cl.LastRenderedText()
		return err == nil && strings.Contains(rows, "typing")
	})
}

// TestReconnectAfterRedial covers the Ctrl-Z detach/reconnect path: the client
// re-dials onto a fresh UDP 5-tuple, the server roams to follow it, and the
// session keeps working afterwards with its sequence numbers intact.
//
// This test was skipped while the send side stalled after a re-dial.  The
// cause was not the re-dial at all: nextWait collapsed both the "idle" and the
// "due now" timer results into a one-second sleep, so nothing left the client
// until a timer happened to expire.
func TestReconnectAfterRedial(t *testing.T) {
	cl, srv, conn, cleanup := mkSession(t)
	defer cleanup()

	cl.PushInput([]byte("before\r"))
	waitFor(t, "pre-detach echo", func() bool {
		return strings.Contains(screenText(t, cl), "before")
	})
	portBefore := localPort(conn)

	// Ctrl-^ then Ctrl-Z, on a fresh line: the detach sequence.
	cl.PushInput([]byte{0x1E, 0x1A})
	waitFor(t, "the socket to be re-dialed", func() bool {
		return localPort(conn) != portBefore
	})

	// Enter reattaches.
	cl.PushInput([]byte("\r"))

	// Distinguish "the loop died" from "the loop stalled": the first is a
	// lifecycle bug, the second a timer bug, and they read very differently in a
	// failure report.
	if !cl.Running() {
		t.Fatal("the event loop stopped after the re-dial; nothing was going to be sent")
	}

	// A keystroke typed after reattaching must reach the server promptly.
	// The bound is generous compared to the measured round trip (~60 ms over
	// loopback) but far tighter than the one-second timer floor that used to
	// mask the stall.
	txBefore := atomic.LoadUint64(&conn.TxTotal)
	sent := make(chan time.Duration, 1)
	go func() {
		t0 := time.Now()
		cl.PushInput([]byte("after\r"))
		for time.Now().Before(t0.Add(5 * time.Second)) {
			if atomic.LoadUint64(&conn.TxTotal) > txBefore {
				sent <- time.Since(t0)
				return
			}
			time.Sleep(time.Millisecond)
		}
		sent <- time.Since(t0)
	}()
	if d := <-sent; d > 500*time.Millisecond {
		t.Fatalf("post-redial keystroke took %v to transmit; the send side has stalled", d)
	}

	waitFor(t, "post-redial echo", func() bool {
		return strings.Contains(screenText(t, cl), "after")
	})
	addr := conn.LocalAddr()
	if addr == nil || !srv.ConnRoamedTo(addr) {
		t.Fatalf("server did not roam to the re-dialed client address %v", addr)
	}
}

// TestPredictionEchoCancellationIntegration exercises the full path: type
// before the server answers, then make sure the authoritative echo replaces
// the speculation instead of being drawn a second time.
func TestPredictionEchoCancellationIntegration(t *testing.T) {
	key, err := moshcrypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := fakeserver.New(key, lo(0), fakeserver.Options{Cols: 80, Rows: 24, Echo: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, err := transport.NewClientConnection(key, lo(srv.Port()), transport.ConnOptions{BindIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	srv.Attach(conn.LocalAddr())
	tr := transport.NewTransport(conn, &state.UserStream{}, vt.NewTerminalState(80, 24))
	tr.Sender.SetSendDelay(time.Millisecond)
	cl := session.New(nil, tr, 80, 24, session.Options{
		Predict:    session.PredictAlways,
		EscapeKey:  -1,
		NoTermInit: true,
		ServerHost: "127.0.0.1",
		ServerPort: srv.Port(),
	})
	go func() { _ = cl.Run() }()
	defer cl.Stop()

	// Do not service the server yet.  Seeing the text now proves it came from
	// the prediction layer rather than from a remote echo.
	cl.PushInput([]byte("hello"))
	waitFor(t, "local prediction before server reply", func() bool {
		text, err := cl.LastRenderedText()
		return err == nil && strings.Contains(text, "hello")
	})

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := srv.ServeOnce(time.Now().Add(2 * time.Millisecond)); err != nil {
				return
			}
		}
	}()

	waitFor(t, "authoritative server echo", func() bool {
		return strings.Contains(screenText(t, cl), "hello")
	})
	// Give the client time to reconcile the echoed state and remove the
	// speculative layer.
	time.Sleep(150 * time.Millisecond)
	text, err := cl.LastRenderedText()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(text, "hello"); got != 1 {
		t.Fatalf("rendered %d copies of hello after echo:\n%s", got, text)
	}
}
