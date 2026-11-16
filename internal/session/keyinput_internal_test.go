package session

import (
	"bytes"
	"testing"

	"winsh/internal/consoleapi"
)

func keyEvent(vk uint16, state uint32, ch uint16) consoleapi.KeyEvent {
	return consoleapi.KeyEvent{
		KeyDown:      true,
		RepeatCount:  1,
		VirtualKey:   vk,
		VirtualState: state,
		CharCode:     ch,
	}
}

func TestEncodeNavigationKeysUsesCursorMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		vk        uint16
		normal    string
		appCursor string
	}{
		{"up", vkUp, "\x1b[A", "\x1bOA"},
		{"down", vkDown, "\x1b[B", "\x1bOB"},
		{"right", vkRight, "\x1b[C", "\x1bOC"},
		{"left", vkLeft, "\x1b[D", "\x1bOD"},
		{"home", vkHome, "\x1b[H", "\x1bOH"},
		{"end", vkEnd, "\x1b[F", "\x1bOF"},
		{"insert", vkInsert, "\x1b[2~", "\x1b[2~"},
		{"delete", vkDelete, "\x1b[3~", "\x1b[3~"},
		{"page up", vkPrior, "\x1b[5~", "\x1b[5~"},
		{"page down", vkNext, "\x1b[6~", "\x1b[6~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normal := &KeyEncoder{}
			if got := normal.Encode(keyEvent(tc.vk, 0, 0)); string(got) != tc.normal {
				t.Fatalf("normal mode = %q, want %q", got, tc.normal)
			}

			app := &KeyEncoder{}
			app.SetApplicationCursor(true)
			if got := app.Encode(keyEvent(tc.vk, 0, 0)); string(got) != tc.appCursor {
				t.Fatalf("application mode = %q, want %q", got, tc.appCursor)
			}
		})
	}
}

func TestSessionUsesMoshApplicationCursorKeys(t *testing.T) {
	c := New(nil, nil, 80, 24, Options{})
	for _, tc := range []struct {
		name string
		vk   uint16
		want string
	}{
		{"up", vkUp, "\x1bOA"},
		{"down", vkDown, "\x1bOB"},
		{"right", vkRight, "\x1bOC"},
		{"left", vkLeft, "\x1bOD"},
		{"home", vkHome, "\x1bOH"},
		{"end", vkEnd, "\x1bOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.enc.Encode(keyEvent(tc.vk, 0, 0)); string(got) != tc.want {
				t.Fatalf("session key = %q, want mosh application-mode %q", got, tc.want)
			}
		})
	}
}

func TestEncodeNavigationKeysCarriesModifiers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		vk    uint16
		state uint32
		want  string
	}{
		{"Ctrl-Up", vkUp, leftCtrlPressed, "\x1b[1;5A"},
		{"Ctrl-Down", vkDown, leftCtrlPressed, "\x1b[1;5B"},
		{"Ctrl-Right", vkRight, leftCtrlPressed, "\x1b[1;5C"},
		{"Ctrl-Left", vkLeft, leftCtrlPressed, "\x1b[1;5D"},
		{"Ctrl-Home", vkHome, leftCtrlPressed, "\x1b[1;5H"},
		{"Ctrl-End", vkEnd, leftCtrlPressed, "\x1b[1;5F"},
		{"Shift-Home", vkHome, shiftPressed, "\x1b[1;2H"},
		{"Alt-End", vkEnd, leftAltPressed, "\x1b[1;3F"},
		{"Shift-Alt-Ctrl-Left", vkLeft, shiftPressed | leftAltPressed | leftCtrlPressed, "\x1b[1;8D"},
		{"Ctrl-Insert", vkInsert, leftCtrlPressed, "\x1b[2;5~"},
		{"Ctrl-Delete", vkDelete, leftCtrlPressed, "\x1b[3;5~"},
		{"Ctrl-PageUp", vkPrior, leftCtrlPressed, "\x1b[5;5~"},
		{"Ctrl-PageDown", vkNext, leftCtrlPressed, "\x1b[6;5~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &KeyEncoder{}
			if got := k.Encode(keyEvent(tc.vk, tc.state, 0)); string(got) != tc.want {
				t.Fatalf("Encode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestModifiedNavigationSequenceIgnoresApplicationCursorMode(t *testing.T) {
	k := &KeyEncoder{}
	k.SetApplicationCursor(true)
	if got := k.Encode(keyEvent(vkUp, leftCtrlPressed, 0)); string(got) != "\x1b[1;5A" {
		t.Fatalf("Ctrl-Up in application mode = %q, want CSI 1;5A", got)
	}
}

func TestControlKeyBitsMatchWindows(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state uint32
		shift bool
		alt   bool
		ctrl  bool
	}{
		{"right Alt", 0x0001, false, true, false},
		{"left Alt", 0x0002, false, true, false},
		{"right Ctrl", 0x0004, false, false, true},
		{"left Ctrl", 0x0008, false, false, true},
		{"Shift", 0x0010, true, false, false},
		{"Shift+left Ctrl", 0x0018, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := keyModifiersFor(tc.state)
			if got.shift != tc.shift || got.alt != tc.alt || got.ctrl != tc.ctrl {
				t.Fatalf("keyModifiersFor(0x%04x) = shift:%v alt:%v ctrl:%v, want shift:%v alt:%v ctrl:%v",
					tc.state, got.shift, got.alt, got.ctrl, tc.shift, tc.alt, tc.ctrl)
			}
		})
	}

	// These are the literal values ReadConsoleInputW puts in
	// dwControlKeyState.  Using the production constants here would let a
	// transposed Shift/Ctrl definition pass its own tests.
	k := &KeyEncoder{}
	if got := k.Encode(keyEvent(vkUp, 0x0010, 0)); string(got) != "\x1b[1;2A" {
		t.Errorf("Shift-Up with SHIFT_PRESSED = %q, want CSI 1;2A", got)
	}
	if got := k.Encode(keyEvent(vkUp, 0x0004, 0)); string(got) != "\x1b[1;5A" {
		t.Errorf("Up with RIGHT_CTRL_PRESSED = %q, want CSI 1;5A", got)
	}
}

func TestEncodeFunctionKeysCarriesModifiers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		vk    uint16
		state uint32
		want  string
	}{
		{"Shift-F1", vkF1, shiftPressed, "\x1b[1;2P"},
		{"Alt-F4", vkF1 + 3, leftAltPressed, "\x1b[1;3S"},
		{"Ctrl-F5", vkF1 + 4, leftCtrlPressed, "\x1b[15;5~"},
		{"Ctrl-Shift-F12", vkF1 + 11, leftCtrlPressed | shiftPressed, "\x1b[24;6~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &KeyEncoder{}
			if got := k.Encode(keyEvent(tc.vk, tc.state, 0)); string(got) != tc.want {
				t.Fatalf("Encode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEncodeRepeatsHeldKeys(t *testing.T) {
	for _, tc := range []struct {
		name   string
		event  consoleapi.KeyEvent
		repeat uint16
		want   string
	}{
		{"arrow", keyEvent(vkRight, 0, 0), 3, "\x1b[C\x1b[C\x1b[C"},
		{"text", keyEvent(0x41, 0, 'a'), 3, "aaa"},
		{"zero means one", keyEvent(vkUp, 0, 0), 0, "\x1b[A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.event.RepeatCount = tc.repeat
			k := &KeyEncoder{}
			if got := k.Encode(tc.event); string(got) != tc.want {
				t.Fatalf("Encode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEncodeAltStillPrefixesCharacterKeys(t *testing.T) {
	k := &KeyEncoder{}
	got := k.Encode(keyEvent(0x46, leftAltPressed, 'f'))
	if !bytes.Equal(got, []byte("\x1bf")) {
		t.Fatalf("Alt-f = % x, want 1b 66", got)
	}
}
