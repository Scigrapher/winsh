package session

import (
	"strings"
	"testing"
	"time"
)

// White-box tests for the notice the user sees the moment the escape key is
// pressed.  It is the only place the hotkey grammar is documented at runtime, so
// its wording is part of the fix: it used to print the raw byte, which read as
// `gives literal "\x1e"` and told the user nothing.

func TestEscapeHelpSpellsOutTheCommands(t *testing.T) {
	c := &Client{opt: Options{EscapeKey: 0x1E}}
	got := c.escapeHelp()
	for _, want := range []string{"Ctrl-Z", `"."`, "Ctrl-^", "detaches", "quits"} {
		if !contains(got, want) {
			t.Errorf("escapeHelp() = %q, missing %q", got, want)
		}
	}
	if contains(got, `\x1e`) || contains(got, "\x1e") {
		t.Errorf("escapeHelp() leaks a raw escape byte: %q", got)
	}
}

func TestEscapeKeyAndPassKeyNames(t *testing.T) {
	ctrl := &Client{opt: Options{EscapeKey: 0x1E}}
	if got := ctrl.escapeKeyName(); got != "Ctrl-^" {
		t.Errorf("escapeKeyName for Ctrl-^ = %q, want Ctrl-^", got)
	}
	if ctrl.passKey() != '^' || ctrl.passKey2() != '^' {
		t.Errorf("pass keys for Ctrl-^ = %q %q, want ^ ^", ctrl.passKey(), ctrl.passKey2())
	}
	printable := &Client{opt: Options{EscapeKey: '~'}}
	if got := printable.escapeKeyName(); got != "\"~\"" {
		t.Errorf("escapeKeyName for a printable escape = %q, want \"~\"", got)
	}
	// With a printable escape key the pass key is the escape key itself, so the
	// only way to type it is the second pass key; mosh accepts either.
	if printable.passKey() != '~' {
		t.Errorf("passKey for a printable escape = %q, want ~", printable.passKey())
	}
}

// The connect hint is the only thing that tells a first-time user how to leave,
// so it has to name the key in words and stay out of the way otherwise: not for a
// one-shot remote command, not with the escape key switched off.
func TestConnectHintTeachesTheExitKey(t *testing.T) {
	c := &Client{opt: Options{EscapeKey: 0x1E}}
	c.maybeShowConnectHint()
	if !strings.Contains(c.notif, "Ctrl-^") {
		t.Fatalf("connect hint does not name the escape key: %q", c.notif)
	}
	for _, want := range []string{"quits", "detaches", "--help"} {
		if !strings.Contains(c.notif, want) {
			t.Errorf("connect hint missing %q: %q", want, c.notif)
		}
	}
	if len(c.notif) > 76 {
		t.Errorf("connect hint is %d bytes and would be truncated on an 80-column screen: %q", len(c.notif), c.notif)
	}
	if c.notifSticky {
		t.Error("the connect hint must be transient, not sticky")
	}

	noEscape := &Client{opt: Options{EscapeKey: -1}}
	noEscape.maybeShowConnectHint()
	if noEscape.notif != "" {
		t.Errorf("a session with no escape key still advertised one: %q", noEscape.notif)
	}
	command := &Client{opt: Options{EscapeKey: 0x1E, HaveRemoteCommand: true}}
	command.maybeShowConnectHint()
	if command.notif != "" {
		t.Errorf("a one-shot remote command got an interactive banner: %q", command.notif)
	}
}

// setNotification has always recorded a four-second deadline for transient
// notices, but nothing ever read it: a one-off "Network error" stayed on the
// bottom row until the session ended.
func TestTransientNotificationsExpireAndStickyOnesDoNot(t *testing.T) {
	now := time.Now()
	c := &Client{}
	c.setNotification("Network error: connection refused", false)
	c.expireNotification(now.Add(3 * time.Second))
	if c.notif == "" {
		t.Fatal("the notice vanished early")
	}
	c.expireNotification(now.Add(5 * time.Second))
	if c.notif != "" {
		t.Errorf("a transient notice never expired: %q", c.notif)
	}

	c.setNotification("Exiting on user request...", true)
	c.expireNotification(now.Add(time.Hour))
	if c.notif == "" {
		t.Error("the sticky notice telling the user they are leaving must not vanish")
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
