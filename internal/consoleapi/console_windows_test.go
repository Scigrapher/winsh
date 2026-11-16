package consoleapi

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// isConsoleHandle answers "is this handle a console?".  consoleMode returns an
// error, so the polarity is one character wide, and it used to be wrong in both
// flags at once -- which silently disabled raw mode, virtual-terminal output, and
// console key events in exactly the situation where they are needed: a real
// console.  Everything a user would call "my escape key does nothing" lives
// downstream of this predicate.
func TestIsConsoleHandleClassifiesHandles(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	for _, tc := range []struct {
		name string
		h    syscall.Handle
	}{
		{"pipe read end", syscall.Handle(pr.Fd())},
		{"pipe write end", syscall.Handle(pw.Fd())},
		{"invalid handle", syscall.InvalidHandle},
		{"zero handle", 0},
	} {
		if isConsoleHandle(tc.h) {
			t.Errorf("isConsoleHandle(%s) = true; only a console may answer true", tc.name)
		}
	}

	f, err := os.OpenFile("NUL", os.O_RDWR, 0)
	if err == nil {
		defer f.Close()
		if isConsoleHandle(syscall.Handle(f.Fd())) {
			t.Error("isConsoleHandle(NUL) = true; the null device is not a console")
		}
	}
}

// A redirected stdio is the normal shape of a scripted run, and it must be
// recognised as such: the connect hint, the raw-mode call, and the choice of
// input source all hang off these two flags.
func TestOpenWithRedirectedStdioReportsNoConsole(t *testing.T) {
	if isConsoleHandle(stdHandle(stdInputHandle)) || isConsoleHandle(stdHandle(stdOutputHandle)) {
		t.Skip("this test process is attached to a console; nothing to check")
	}
	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if c.stdinIsConsole {
		t.Error("Open called a redirected stdin a console")
	}
	if c.stdoutIsConsole {
		t.Error("Open called a redirected stdout a console")
	}
	if c.InputIsConsole() {
		t.Error("InputIsConsole disagrees with the flag")
	}
}

// record builds an INPUT_RECORD out of the exact bytes ReadConsoleInputW puts
// on the wire, so that these tests say something about the Windows structure
// layout rather than about Go.
func record(t *testing.T, hex string) *inputRecord {
	t.Helper()
	if got := unsafe.Sizeof(inputRecord{}); got != 20 {
		t.Fatalf("inputRecord is %d bytes; Windows INPUT_RECORD is 20", got)
	}
	out := recordBytes(t, hex)
	rec := &inputRecord{}
	copy(rec.data[:], out[4:])
	rec.EventType = uint16(out[0]) | uint16(out[1])<<8
	return rec
}

// ReadConsoleInputW writes records contiguously at the ABI size.  A Go struct
// larger than 20 bytes decodes the first record correctly and every subsequent
// record from the wrong offset, which silently drops batched keystrokes.
func TestInputRecordBatchStaysAligned(t *testing.T) {
	raw := append(recordBytes(t, rawKeyADown), recordBytes(t, rawKeyAUp)...)
	records := unsafe.Slice((*inputRecord)(unsafe.Pointer(&raw[0])), 2)

	down := records[0].key()
	if !down.KeyDown || down.CharCode != 'a' {
		t.Fatalf("first record = %+v, want key-down for 'a'", down)
	}
	up := records[1].key()
	if up.KeyDown || up.VirtualKey != 0x41 || up.CharCode != 'a' {
		t.Fatalf("second record = %+v, want key-up for VK_A", up)
	}
}

func recordBytes(t *testing.T, hex string) []byte {
	t.Helper()
	var out []byte
	for _, tok := range strings.Fields(hex) {
		b, err := strconv.ParseUint(tok, 16, 8)
		if err != nil {
			t.Fatalf("bad byte %q: %v", tok, err)
		}
		out = append(out, byte(b))
	}
	if len(out) != 20 {
		t.Fatalf("INPUT_RECORD is 20 bytes, got %d", len(out))
	}
	return out
}

// The two records ReadConsoleInputW really delivered for a single press of the
// "a" key on this machine, verbatim: a key-DOWN carrying the character, then a
// key-UP carrying the virtual key.  bKeyDown is a BOOLEAN with three bytes of
// padding after it, so reading it as a WORD -- as this file once did -- slides
// every later field two bytes to the left: the repeat count becomes the
// virtual-key code, the scan code becomes the character, and half of the
// character becomes the control-key state.  Keystrokes then turned into control
// bytes nobody pressed, which is the other half of "Ctrl-^ does not work".
const rawKeyADown = "01 00 00 00 01 00 00 00 01 00 00 00 00 00 61 00 00 00 00 00"
const rawKeyAUp = "01 00 00 00 00 00 00 00 01 00 41 00 1e 00 61 00 00 00 00 00"

func TestKeyRecordDecodesTheWindowsLayout(t *testing.T) {
	down := record(t, rawKeyADown).key()
	if !down.KeyDown {
		t.Error("the key-DOWN record decoded as a key release; the filter that stops released keys echoing depends on this")
	}
	if down.CharCode != 'a' {
		t.Errorf("CharCode = %q, want 'a'", rune(down.CharCode))
	}
	if down.RepeatCount != 1 {
		t.Errorf("RepeatCount = %d, want 1", down.RepeatCount)
	}

	up := record(t, rawKeyAUp).key()
	if up.KeyDown {
		t.Error("the key-UP record decoded as a key press, which would echo every key twice")
	}
	if up.VirtualKey != 0x41 {
		t.Errorf("VirtualKey = 0x%02x, want 0x41", up.VirtualKey)
	}
	if up.CharCode != 'a' {
		t.Errorf("up CharCode = %q, want 'a'", rune(up.CharCode))
	}
}

// Ctrl-Shift-6, which is what mosh's escape key is on a US keyboard: the console
// reports it as the already-decoded control character 0x1E with the shift and
// left-control bits in the control-key state.  Both halves have to survive the
// decode for the session to see the escape at all.
func TestKeyRecordDecodesCtrlShiftSix(t *testing.T) {
	rec := record(t, "01 00 00 00 01 00 00 00 01 00 36 00 07 00 1e 00 18 00 00 00")
	k := rec.key()
	if !k.KeyDown {
		t.Fatal("not a key press")
	}
	if k.VirtualKey != 0x36 {
		t.Errorf("VirtualKey = 0x%02x, want 0x36", k.VirtualKey)
	}
	if k.CharCode != 0x1E {
		t.Errorf("CharCode = 0x%02x, want 0x1E", k.CharCode)
	}
	if want := uint32(0x0010 | 0x0008); k.VirtualState != want {
		t.Errorf("VirtualState = 0x%04x, want 0x%04x (SHIFT_PRESSED|LEFT_CTRL_PRESSED)", k.VirtualState, want)
	}
}

// A function-key press, whose CharCode is zero and whose VirtualKey is all the
// encoder has to go on.
func TestKeyRecordDecodesAPressWithoutACharacter(t *testing.T) {
	rec := record(t, "01 00 00 00 01 00 00 00 01 00 24 00 47 00 00 00 00 01 00 00")
	k := rec.key()
	if k.VirtualKey != 0x24 || k.CharCode != 0 {
		t.Errorf("decoded vk=0x%02x ch=0x%02x, want vk=0x24 ch=0", k.VirtualKey, k.CharCode)
	}
	if k.VirtualState&0x0100 == 0 {
		t.Error("ENHANCEDKEY bit lost")
	}
}

// WINDOW_BUFFER_SIZE_EVENT carries a COORD at the start of the union.
func TestSizeRecordDecodes(t *testing.T) {
	rec := record(t, "04 00 00 00 78 00 32 00 00 00 00 00 00 00 00 00 00 00 00 00")
	if rec.EventType != windowBufferSizeEvent {
		t.Fatalf("EventType = %d, want %d", rec.EventType, windowBufferSizeEvent)
	}
	c := rec.size()
	if c.X != 120 || c.Y != 50 {
		t.Errorf("size = %dx%d, want 120x50", c.X, c.Y)
	}
}

// ReadEvents has two entirely separate sources: the console input buffer, and
// os.Stdin for redirected input.  A handle that is not a console must not be
// allowed to take the console branch, where ReadConsoleInputW would fail and the
// reader goroutine would quietly stop delivering keystrokes -- which is exactly
// how a session ends up with no input at all.
func TestReadEventsRefusesANonConsoleHandle(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	c := &Console{in: syscall.Handle(pr.Fd()), stdinIsConsole: true}
	if _, err := c.ReadEvents(); err == nil {
		t.Error("ReadEvents accepted a pipe as a console input handle")
	}
}
