package session

import (
	"strconv"
	"unicode/utf16"

	"winsh/internal/consoleapi"
)

// Console key events are translated into the byte sequences a VT terminal
// would emit.  Doing it here rather than relying on the console's own
// processing is what lets winsh honour application-cursor-keys mode, which the
// server's terminal sets and which changes what the arrow keys must send.

// Virtual-key codes used below.
const (
	vkBack    = 0x08
	vkTab     = 0x09
	vkClear   = 0x0C
	vkReturn  = 0x0D
	vkShift   = 0x10
	vkControl = 0x11
	vkMenu    = 0x12
	vkPause   = 0x13
	vkCapital = 0x14
	vkEscape  = 0x1B
	vkSpace   = 0x20
	vkPrior   = 0x21
	vkNext    = 0x22
	vkEnd     = 0x23
	vkHome    = 0x24
	vkLeft    = 0x25
	vkUp      = 0x26
	vkRight   = 0x27
	vkDown    = 0x28
	vkInsert  = 0x2D
	vkDelete  = 0x2E
	vkHelp    = 0x2F
	vkLWin    = 0x5B
	vkApps    = 0x5D
	vkF1      = 0x70
)

// Control-key state bits.
const (
	rightAltPressed  = 0x0001
	leftAltPressed   = 0x0002
	rightCtrlPressed = 0x0004
	leftCtrlPressed  = 0x0008
	shiftPressed     = 0x0010
	enhancedKey      = 0x0100
)

// KeyEncoder turns console key events into terminal bytes.  It is stateful
// only for UTF-16 surrogate pairing.
type KeyEncoder struct {
	appCursor     bool
	highSurrogate rune
}

// SetApplicationCursor selects the DECCKM encoding for arrows, Home, and End.
func (k *KeyEncoder) SetApplicationCursor(v bool) { k.appCursor = v }

// Encode returns the bytes a key event should send to the server, or nil when
// the event should be ignored (modifier-only presses, unknown keys).
func (k *KeyEncoder) Encode(e consoleapi.KeyEvent) []byte {
	out := k.encode(e)
	repeat := int(e.RepeatCount)
	if repeat <= 1 || len(out) == 0 {
		return out
	}
	// ReadConsoleInputW consolidates a held key into one event carrying a
	// repeat count.  Sending only one sequence makes arrows, Home/End, and
	// ordinary text stop after the first repeat.
	repeated := make([]byte, 0, len(out)*repeat)
	for i := 0; i < repeat; i++ {
		repeated = append(repeated, out...)
	}
	return repeated
}

func (k *KeyEncoder) encode(e consoleapi.KeyEvent) []byte {
	mods := keyModifiersFor(e.VirtualState)
	ctrl := mods.ctrl
	alt := mods.alt

	// Function keys and navigation keys first: their CharCode is 0.
	if seq, ok := k.special(e.VirtualKey, mods); ok {
		return seq
	}

	var prefix []byte
	if alt {
		prefix = append(prefix, 0x1B)
	}

	ch := rune(e.CharCode)
	if ch == 0 || ch == 0xE0 {
		// Ctrl-Space is reported as VK_SPACE carrying no character at all,
		// while a bare modifier press carries no character and no usable key
		// code.  Only the first of those is something to send.
		if ctrl && e.VirtualKey == vkSpace {
			return append(prefix, 0)
		}
		return nil
	}
	// Combine surrogate pairs across events.
	if utf16.IsSurrogate(ch) {
		if k.highSurrogate != 0 {
			// A lone high surrogate followed by another: emit the first as-is.
			out := append([]byte(nil), prefix...)
			out = appendRuneBytes(out, k.highSurrogate)
			k.highSurrogate = 0
		}
		if runeIsHighSurrogate(ch) {
			k.highSurrogate = ch
			return nil
		}
		// A lone low surrogate.
		out := append([]byte(nil), prefix...)
		return appendRuneBytes(out, 0xFFFD)
	}
	if k.highSurrogate != 0 {
		pending := k.highSurrogate
		k.highSurrogate = 0
		out := append([]byte(nil), prefix...)
		out = appendRuneBytes(out, pending)
		prefix = out
	}

	if ctrl {
		// Ctrl-letter maps to the ASCII control code; Ctrl-Space is NUL.
		// The console usually hands over the control code it computed itself:
		// Ctrl-Shift-6 -- mosh's escape key -- arrives as Character 0x1E with
		// Ctrl and Shift both held, not as '^' with Ctrl held, and Ctrl-Shift-1
		// arrives as 0x01.  Recomputing from the character in that case falls
		// through to the "nothing sensible to send" default below and silently
		// eats the keypress, which is how Ctrl-^ came to do nothing at all.
		if ch < 0x20 {
			return append(prefix, byte(ch))
		}
		switch {
		case ch >= '@' && ch <= '_':
			return append(prefix, byte(ch-0x40))
		case ch >= '!' && ch <= '/':
			// The symbols above the digit row, which is how the console reports
			// Ctrl-Shift-1..0 with the shift applied.  Clearing the top three bits
			// is what Ctrl means on every terminal, so this is what turns
			// Ctrl-Shift-6 into the 0x1E that is mosh's escape key when conhost
			// hands over the shifted character instead of the control code.  A bare
			// digit with Ctrl stays unhandled, as it is in xterm.
			return append(prefix, byte(ch&0x1F))
		case ch >= 'a' && ch <= 'z':
			return append(prefix, byte(ch-0x60))
		case ch == ' ':
			return append(prefix, 0)
		case ch == '2':
			return append(prefix, 0)
		case ch == '[':
			return append(prefix, 0x1B)
		case ch == '\\':
			return append(prefix, 0x1C)
		case ch == ']':
			return append(prefix, 0x1D)
		case ch == '^':
			return append(prefix, 0x1E)
		case ch == '_':
			return append(prefix, 0x1F)
		default:
			// Nothing sensible to send (Ctrl-F1 etc.).
			return nil
		}
	}

	// The console reports Enter as VK_RETURN with CharCode 13; terminals send
	// CR.  Backspace must be DEL, as every modern terminal does.
	switch e.VirtualKey {
	case vkSpace:
		return append(prefix, ' ')
	}

	if ch < 0x20 {
		return append(prefix, byte(ch))
	}
	out := append([]byte(nil), prefix...)
	return appendRuneBytes(out, ch)
}

// keyModifiers mirrors the dwControlKeyState bits defined by KEY_EVENT_RECORD.
// The values matter: in particular SHIFT_PRESSED is 0x0010 and
// RIGHT_CTRL_PRESSED is 0x0004.  The two were previously transposed here,
// which made Shift look like Ctrl and broke every modified navigation key.
type keyModifiers struct {
	shift bool
	alt   bool
	ctrl  bool
	code  int // xterm modifier parameter: 1 + Shift(1) + Alt(2) + Ctrl(4)
}

func keyModifiersFor(state uint32) keyModifiers {
	m := keyModifiers{
		shift: state&shiftPressed != 0,
		alt:   state&(leftAltPressed|rightAltPressed) != 0,
		ctrl:  state&(leftCtrlPressed|rightCtrlPressed) != 0,
	}
	m.code = 1
	if m.shift {
		m.code++
	}
	if m.alt {
		m.code += 2
	}
	if m.ctrl {
		m.code += 4
	}
	return m
}

func (m keyModifiers) withAlt(seq []byte) []byte {
	if !m.alt {
		return seq
	}
	out := make([]byte, 0, len(seq)+1)
	out = append(out, 0x1B)
	return append(out, seq...)
}

func runeIsHighSurrogate(r rune) bool { return r >= 0xD800 && r <= 0xDBFF }

func appendRuneBytes(b []byte, r rune) []byte {
	var buf [4]byte
	switch {
	case r < 0x80:
		return append(b, byte(r))
	case r < 0x800:
		buf[0] = byte(0xC0 | r>>6)
		buf[1] = byte(0x80 | r&0x3F)
		return append(b, buf[:2]...)
	case r < 0x10000:
		buf[0] = byte(0xE0 | r>>12)
		buf[1] = byte(0x80 | r>>6&0x3F)
		buf[2] = byte(0x80 | r&0x3F)
		return append(b, buf[:3]...)
	default:
		buf[0] = byte(0xF0 | r>>18)
		buf[1] = byte(0x80 | r>>12&0x3F)
		buf[2] = byte(0x80 | r>>6&0x3F)
		buf[3] = byte(0x80 | r&0x3F)
		return append(b, buf[:4]...)
	}
}

// special maps navigation and function keys.  The second result reports
// whether the key is known at all; a nil sequence with true means "known but
// sends nothing".
func (k *KeyEncoder) special(vk uint16, mods keyModifiers) ([]byte, bool) {
	csi := func(s string) []byte { return []byte("\x1b[" + s) }
	ss3 := func(c byte) []byte { return []byte("\x1bO" + string(c)) }
	cursor := func(c byte) []byte {
		if mods.code > 1 {
			return csi("1;" + strconv.Itoa(mods.code) + string(c))
		}
		if k.appCursor {
			return ss3(c)
		}
		return csi(string(c))
	}
	tilde := func(code string) []byte {
		if mods.code > 1 {
			return csi(code + ";" + strconv.Itoa(mods.code) + "~")
		}
		return csi(code + "~")
	}
	switch vk {
	case vkUp:
		return cursor('A'), true
	case vkDown:
		return cursor('B'), true
	case vkRight:
		return cursor('C'), true
	case vkLeft:
		return cursor('D'), true
	case vkHome:
		return cursor('H'), true
	case vkEnd:
		return cursor('F'), true
	case vkInsert:
		return tilde("2"), true
	case vkDelete:
		return tilde("3"), true
	case vkPrior:
		return tilde("5"), true
	case vkNext:
		return tilde("6"), true
	case vkTab:
		if mods.shift {
			return mods.withAlt(csi("Z")), true
		}
		return mods.withAlt([]byte{'\t'}), true
	case vkBack:
		return mods.withAlt([]byte{0x7F}), true
	case vkReturn:
		return mods.withAlt([]byte{'\r'}), true
	case vkEscape:
		return mods.withAlt([]byte{0x1B}), true
	case vkPause:
		return mods.withAlt([]byte{0x1A}), true
	case vkHelp:
		return tilde("1"), true
	case vkShift, vkControl, vkMenu, vkCapital, vkLWin, vkApps, vkClear:
		return nil, true // modifiers send nothing on their own
	}
	if vk >= vkF1 && vk <= vkF1+11 {
		// xterm-style encodings, which every mainstream server-side
		// application expects.
		index := int(vk - vkF1)
		if index < 4 {
			if mods.code > 1 {
				return csi("1;" + strconv.Itoa(mods.code) + string("PQRS"[index])), true
			}
			return ss3("PQRS"[index]), true
		}
		table := []string{"15", "17", "18", "19", "20", "21", "23", "24"}
		return tilde(table[index-4]), true
	}
	return nil, false
}
