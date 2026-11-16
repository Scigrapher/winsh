package session_test

import (
	"strings"
	"testing"
	"time"

	"winsh/internal/consoleapi"
	"winsh/internal/fakeserver"
	"winsh/internal/moshcrypto"
	"winsh/internal/session"
	"winsh/internal/state"
	"winsh/internal/transport"
	"winsh/internal/vt"
)

// mosh's escape key is Ctrl-^ (0x1E), and because it is a control character it
// does NOT have to follow a newline.  Both halves of that rule were wrong here:
// the session demanded a newline before any escape key would arm, and the
// console decoder dropped the keypress outright because conhost reports
// Ctrl-Shift-6 as the character 0x1E rather than as '^' held with Ctrl.  A user
// who cannot find the way out of a session has no way to tell those two bugs
// apart, so both are pinned here against the reference grammar in mosh's
// src/frontend/stmclient.cc.

const moshEscapeKey = 0x1E // Ctrl-^

// runEscape starts a session against a local fake mosh-server that echoes what
// it receives, with the escape key set to what the caller asks for.
func runEscape(t *testing.T, escapeKey int) (*session.Client, *transport.Sender, func()) {
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
		EscapeKey:  escapeKey,
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
	return cl, tr.Sender, func() {
		close(stop)
		cl.Stop()
		conn.Close()
		srv.Close()
	}
}

// TestControlEscapeArmsWithoutANewline is the regression test for the "Ctrl-^
// does nothing" complaint: the user has typed half a line, decides to leave,
// and presses Ctrl-^ then period.
func TestControlEscapeArmsWithoutANewline(t *testing.T) {
	cl, sender, cleanup := runEscape(t, moshEscapeKey)
	defer cleanup()

	cl.PushInput([]byte("half a line, no Enter"))
	waitFor(t, "the text to be echoed", func() bool {
		return strings.Contains(screenText(t, cl), "half a line")
	})

	cl.PushInput([]byte{moshEscapeKey, '.'})
	waitFor(t, "the shutdown to start", func() bool { return sender.ShutdownInProgress() })
}

// TestEscapeFollowedByAnOrdinaryByteSendsBoth covers mosh's rule that the escape
// key followed by anything that is neither "." nor Ctrl-Z is ordinary input:
// both bytes go to the server and the session certainly does not exit.
func TestEscapeFollowedByAnOrdinaryByteSendsBoth(t *testing.T) {
	cl, sender, cleanup := runEscape(t, moshEscapeKey)
	defer cleanup()

	cl.PushInput([]byte{moshEscapeKey, 'x'})
	// "x" is deliberate: it is the one echoed letter that does not occur in the
	// help notice painted on the screen, so a match can only be the echo.
	waitFor(t, "the x to be echoed back", func() bool {
		return strings.Contains(screenText(t, cl), "x")
	})
	if sender.ShutdownInProgress() {
		t.Error("escape followed by an ordinary character started a shutdown")
	}
	if !cl.Running() {
		t.Error("the session exited on an escape sequence that should have been literal input")
	}
}

// TestEscapePassKeyTypesTheEscapeItself is mosh's way to send a literal Ctrl-^:
// press the escape key, then the same key without Ctrl.
func TestEscapePassKeyTypesTheEscapeItself(t *testing.T) {
	cl, sender, cleanup := runEscape(t, moshEscapeKey)
	defer cleanup()

	cl.PushInput([]byte("value="))
	waitFor(t, "the prefix to be echoed", func() bool {
		return strings.Contains(screenText(t, cl), "value=")
	})
	cl.PushInput([]byte{moshEscapeKey, '^'})
	time.Sleep(200 * time.Millisecond)
	if sender.ShutdownInProgress() {
		t.Error("the pass key was treated as a command")
	}
	if !cl.Running() {
		t.Error("the session exited when the pass key should have typed a literal Ctrl-^")
	}
}

// TestPrintableEscapeRequiresANewline covers the other half of mosh's rule: a
// printable escape key must follow a newline, so that typing it in ordinary
// input stays possible.
func TestPrintableEscapeRequiresANewline(t *testing.T) {
	cl, sender, cleanup := runEscape(t, 0x7E) // tilde
	defer cleanup()

	cl.PushInput([]byte("text then "))
	cl.PushInput([]byte{0x7E, '.'})
	time.Sleep(250 * time.Millisecond)
	if sender.ShutdownInProgress() {
		t.Error("a printable escape armed mid-line; mosh requires a newline first")
	}
	if !cl.Running() {
		t.Error("a printable escape mid-line ended the session")
	}

	cl.PushInput([]byte("\r"))
	cl.PushInput([]byte{0x7E, '.'})
	waitFor(t, "the shutdown after a newline", func() bool { return sender.ShutdownInProgress() })
}

// TestControlEscapeStillArmsAfterANewline guards the other direction: the fix
// must not have broken the case that used to work.
func TestControlEscapeStillArmsAfterANewline(t *testing.T) {
	cl, sender, cleanup := runEscape(t, moshEscapeKey)
	defer cleanup()

	cl.PushInput([]byte("done\r"))
	cl.PushInput([]byte{moshEscapeKey, '.'})
	waitFor(t, "the shutdown to start", func() bool { return sender.ShutdownInProgress() })
}

// TestEscapeKeyDisabledNeverArms checks --no-escape-key: every byte, including
// the would-be escape key, is ordinary input.  This is the documented way out
// for a terminal that swallows Ctrl-Shift-6.
func TestEscapeKeyDisabledNeverArms(t *testing.T) {
	cl, sender, cleanup := runEscape(t, -1)
	defer cleanup()

	cl.PushInput([]byte{moshEscapeKey, '.'})
	time.Sleep(250 * time.Millisecond)
	if sender.ShutdownInProgress() {
		t.Error("the escape armed even though it is disabled")
	}
	if !cl.Running() {
		t.Error("the session exited although the escape key is disabled")
	}
}

// The console decoder is tested separately because the bug it held was invisible
// to everything above: PushInput delivers bytes that have already been decoded,
// so only a test of Encode can catch a key the console reports but winsh throws
// away.

func kevent(vk uint16, state uint32, ch uint16) consoleapi.KeyEvent {
	return consoleapi.KeyEvent{KeyDown: true, VirtualKey: vk, VirtualState: state, CharCode: ch}
}

const (
	stCtrl  = 0x0008 | 0x0004 // LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED
	stShift = 0x0010          // SHIFT_PRESSED
)

func TestEncodeControlKeys(t *testing.T) {
	k := &session.KeyEncoder{}
	for _, tc := range []struct {
		name string
		ev   consoleapi.KeyEvent
		want []byte
	}{
		// conhost hands over the control code it computed itself, with Ctrl and
		// Shift held.  This is mosh's escape key, and it used to be dropped.
		{"Ctrl-^ as a control code", kevent(0x36, stCtrl|stShift, 0x1E), []byte{0x1E}},
		// Other terminals report the shifted character with Ctrl held.
		{"Ctrl-^ as '^'", kevent(0x36, stCtrl|stShift, '^'), []byte{0x1E}},
		{"Ctrl-C", kevent(0x43, stCtrl, 0x03), []byte{3}},
		{"Ctrl-C as a letter", kevent(0x43, stCtrl, 'C'), []byte{3}},
		{"Ctrl-D", kevent(0x44, stCtrl, 'D'), []byte{4}},
		{"Ctrl-L", kevent(0x4C, stCtrl, 'L'), []byte{12}},
		{"Ctrl-T", kevent(0x54, stCtrl, 'T'), []byte{20}},
		{"Ctrl-Space", kevent(0x20, stCtrl, 0x00), []byte{0}},
		{"Ctrl-[ is ESC", kevent(0xDB, stCtrl, '['), []byte{0x1B}},
		{"Ctrl-@ is NUL", kevent(0x32, stCtrl|stShift, '@'), []byte{0}},
		{"Ctrl-_ is 0x1F", kevent(0x37, stCtrl|stShift, '_'), []byte{0x1F}},
		// Ordinary input must be untouched.
		{"plain a", kevent(0x41, 0, 'a'), []byte("a")},
		{"plain slash", kevent(0xBF, 0, '/'), []byte("/")},
		{"plain newline", kevent(0x0D, 0, 13), []byte("\r")},
		{"backspace is DEL", kevent(0x08, 0, 8), []byte{0x7F}},
	} {
		got := k.Encode(tc.ev)
		if string(got) != string(tc.want) {
			t.Errorf("%s: Encode = % x, want % x", tc.name, got, tc.want)
		}
	}
}

// TestEncodeCtrlShiftDigitRow guards the class of key that arrives either as a
// bare control code or as the shifted symbol above the digit: every terminal
// treats Ctrl as "clear the top three bits", so Ctrl-Shift-6 has to produce the
// 0x1E that is mosh's escape key however conhost chooses to report it.
func TestEncodeCtrlShiftDigitRow(t *testing.T) {
	k := &session.KeyEncoder{}
	for _, tc := range []struct {
		symbol byte
		want   byte
	}{
		{'!', 0x01}, {'@', 0x00}, {'#', 0x03}, {'$', 0x04}, {'%', 0x05},
		{'^', 0x1E}, {'&', 0x06}, {'*', 0x0A}, {'(', 0x08}, {')', 0x09},
	} {
		got := k.Encode(kevent(0x30, stCtrl|stShift, uint16(tc.symbol)))
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("Ctrl-Shift with %q: got % x, want %02x", tc.symbol, got, tc.want)
		}
	}
	// The same keys reported by conhost as already-decoded control codes.
	for c := 0x01; c <= 0x09; c++ {
		got := k.Encode(kevent(0x30, stCtrl|stShift, uint16(c)))
		if len(got) != 1 || got[0] != byte(c) {
			t.Errorf("Ctrl-Shift reporting 0x%02x: got % x", c, got)
		}
	}
}

// TestEncodeAltPrefix checks that Alt still means ESC-prefix rather than being
// eaten by the control-key handling.
func TestEncodeAltPrefix(t *testing.T) {
	k := &session.KeyEncoder{}
	got := k.Encode(kevent(0x46, 0x0002, 'f')) // LEFT_ALT_PRESSED
	if string(got) != "\x1bf" {
		t.Errorf("Alt-f = % x, want 1b 66", got)
	}
}
