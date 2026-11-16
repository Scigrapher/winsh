// Package consoleapi wraps the Windows console API that an interactive client
// needs: raw (unbuffered, unechoed, unprocessed) input, virtual-terminal
// output, and window-size notifications.
//
// It talks to kernel32 directly rather than through a terminal library so that
// winsh stays a single static binary with no third-party code.
package consoleapi

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle               = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procReadConsoleInputW          = kernel32.NewProc("ReadConsoleInputW")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
	procCreateFileW                = kernel32.NewProc("CreateFileW")
	procSetConsoleCtrlHandler      = kernel32.NewProc("SetConsoleCtrlHandler")
)

// winError turns a failed Win32 call into a usable error.
//
// LazyProc.Call hands back a *nil* error whenever the last error code happens
// to be 0, and formatting that with %w yields the unhelpful "%!w(<nil>)" while
// hiding which call failed.  Console entry points do reach that state, so fall
// back to the thread's last error and, failing that, at least name the call.
func winError(what string, e error) error {
	if e == nil {
		if gle := syscall.GetLastError(); gle != nil {
			// A zero Errno carries no information; treat it as absent so the
			// caller gets a named failure instead of a bare code 0.
			if errno, ok := gle.(syscall.Errno); !ok || errno != 0 {
				e = gle
			}
		}
	}
	if e == nil {
		return fmt.Errorf("consoleapi: %s failed", what)
	}
	return fmt.Errorf("consoleapi: %s: %w", what, e)
}

// Console mode flags.
const (
	enableProcessedInput       = 0x0001
	enableLineInput            = 0x0002
	enableEchoInput            = 0x0004
	enableWindowInput          = 0x0008
	enableMouseInput           = 0x0010
	enableQuickEditMode        = 0x0040
	enableExtendedFlags        = 0x0080
	enableVirtualTerminalInput = 0x0200

	enableProcessedOutput       = 0x0001
	enableWrapAtEolOutput       = 0x0002
	enableVirtualTerminalOutput = 0x0004
)

const (
	genericRead        = 0x80000000
	genericWrite       = 0x40000000
	fileShareReadWrite = 0x3
	openExisting       = 3

	stdInputHandle  = -10
	stdOutputHandle = -11
)

// Input record types.
const (
	keyEventRecord        = 1
	mouseEventRecord      = 2
	windowBufferSizeEvent = 4
	menuEventRecord       = 8
	focusEventRecord      = 16
)

type coord struct{ X, Y int16 }
type smallRect struct {
	Left, Top, Right, Bottom int16
}

type consoleScreenBufferInfo struct {
	size              coord
	cursorPosition    coord
	attributes        uint16
	window            smallRect
	maximumWindowSize coord
}

// KeyEvent is a decoded KEY_EVENT_RECORD.
type KeyEvent struct {
	KeyDown      bool
	RepeatCount  uint16
	CharCode     uint16 // UTF-16 code unit
	VirtualKey   uint16
	VirtualState uint32
}

// Event is one console input event.
//
// Kind is "key" (Key set), "resize" (Cols/Rows set), or "raw" (Bytes set, used
// when stdin is a pipe rather than a console).
type Event struct {
	Kind  string
	Key   KeyEvent
	Cols  int
	Rows  int
	Bytes []byte
}

// Console owns the handles and modes needed for an interactive session.
type Console struct {
	in, out syscall.Handle

	savedInMode  uint32
	savedOutMode uint32
	raw          bool

	haveInMode  bool
	haveOutMode bool

	// stdinIsConsole records whether the console input handle is usable; when
	// input is redirected winsh falls back to reading os.Stdin.
	stdinIsConsole  bool
	stdoutIsConsole bool

	mu      sync.Mutex
	closed  bool
	pending []byte // bytes decoded from os.Stdin when not a console
}

// ErrNotConsole reports that a handle is not a console, which is not fatal:
// winsh then falls back to plain byte I/O so that it still works in a pipe.
var ErrNotConsole = errors.New("consoleapi: handle is not a console")

func stdHandle(n int) syscall.Handle {
	r, _, _ := procGetStdHandle.Call(uintptr(n))
	return syscall.Handle(r)
}

// Open returns a Console bound to the standard handles.
func Open() (*Console, error) {
	c := &Console{in: stdHandle(stdInputHandle), out: stdHandle(stdOutputHandle)}
	if c.in == 0 || c.in == syscall.InvalidHandle {
		f, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("consoleapi: open console input: %w", err)
		}
		c.in = syscall.Handle(f.Fd())
	}
	if c.out == 0 || c.out == syscall.InvalidHandle {
		f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("consoleapi: open console output: %w", err)
		}
		c.out = syscall.Handle(f.Fd())
	}
	c.stdinIsConsole = isConsoleHandle(c.in)
	c.stdoutIsConsole = isConsoleHandle(c.out)
	return c, nil
}

// isConsoleHandle reports whether h refers to a console rather than a pipe, a
// file, or the invalid handle.
//
// consoleMode answers with an error, and Go errors are nil on success, so the
// polarity here is easy to get backwards.  It was: Open used to assign
// "consoleMode(h) != nil" to both flags, which meant that in a real console
// winsh believed it had none.  It then skipped EnterRaw entirely -- no raw input
// mode, no ENABLE_VIRTUAL_TERMINAL_PROCESSING on output -- and read keystrokes
// from os.Stdin instead of the console input buffer.  That is what made Ctrl-^
// look dead: line-buffered input parks Ctrl-^ and the "." that follows it in the
// console's line buffer until the user presses Enter, and conhost's own
// key handling gets first refusal on everything else.  All three of the
// "it ignores my window size / my colours / my escape key" complaints trace back
// through this one predicate.
func isConsoleHandle(h syscall.Handle) bool { return consoleMode(h) == nil }

func consoleMode(h syscall.Handle) error {
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return ErrNotConsole
	}
	return nil
}

// EnterRaw puts the console into the mode an interactive session needs: no
// line buffering, no local echo, no arrow-key interception by the console, and
// virtual-terminal processing on output.  It is idempotent.
//
// Input and output are configured independently and failures are collected
// rather than returned early.  That matters: bailing out on an input failure
// used to skip the output handle entirely, leaving it without
// ENABLE_VIRTUAL_TERMINAL_PROCESSING, after which conhost mangles or drops the
// escape sequences the renderer depends on -- including 24-bit colour.  A
// redirected stdin is normal for piped input and must not cost the session its
// ability to paint.
// InputIsConsole reports whether input arrives from a real console rather than
// a redirected or piped stdin.  Decorations that are meant for a human at a
// keyboard -- the connect hint, for instance -- are skipped when it is false.
func (c *Console) InputIsConsole() bool { return c.stdinIsConsole }

func (c *Console) EnterRaw() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw {
		return nil
	}
	var problems []string

	if c.stdinIsConsole {
		var mode uint32
		if r, _, e := procGetConsoleMode.Call(uintptr(c.in), uintptr(unsafe.Pointer(&mode))); r == 0 {
			problems = append(problems, winError("GetConsoleMode(input)", e).Error())
		} else {
			c.savedInMode = mode
			c.haveInMode = true
			// Keep window-size events so resizes are noticed; drop line input,
			// echo, quick-edit, mouse, and the console's own arrow-key handling.
			want := uint32(enableWindowInput | enableExtendedFlags | enableVirtualTerminalInput)
			if r, _, e := procSetConsoleMode.Call(uintptr(c.in), uintptr(want)); r == 0 {
				problems = append(problems, winError("SetConsoleMode(input)", e).Error())
			}
		}
	}

	if c.stdoutIsConsole {
		var mode uint32
		if r, _, e := procGetConsoleMode.Call(uintptr(c.out), uintptr(unsafe.Pointer(&mode))); r == 0 {
			problems = append(problems, winError("GetConsoleMode(output)", e).Error())
		} else {
			c.savedOutMode = mode
			c.haveOutMode = true
			want := uint32(enableProcessedOutput | enableVirtualTerminalOutput)
			if r, _, e := procSetConsoleMode.Call(uintptr(c.out), uintptr(want)); r == 0 {
				problems = append(problems, winError("SetConsoleMode(output)", e).Error())
			}
		}
	}

	c.raw = true
	if len(problems) > 0 {
		// Each entry already names its own API; a second prefix here read as
		// "consoleapi: consoleapi:".
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Restore puts the console modes back the way they were found.  It is safe to
// call repeatedly and from a panic path.
func (c *Console) Restore() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.raw {
		return
	}
	c.raw = false
	if c.haveInMode {
		procSetConsoleMode.Call(uintptr(c.in), uintptr(c.savedInMode))
		c.haveInMode = false
	}
	if c.haveOutMode {
		procSetConsoleMode.Call(uintptr(c.out), uintptr(c.savedOutMode))
		c.haveOutMode = false
	}
}

// Write sends bytes to the terminal.
func (c *Console) Write(p []byte) (int, error) {
	if !c.stdoutIsConsole {
		return os.Stdout.Write(p)
	}
	// Writing through the file handle lets the console's own virtual-terminal
	// engine do the rendering.
	var n uint32
	var optr *byte
	if len(p) > 0 {
		optr = &p[0]
	}
	r, _, e2 := procWriteFile.Call(
		uintptr(c.out),
		uintptr(unsafe.Pointer(optr)),
		uintptr(len(p)),
		uintptr(unsafe.Pointer(&n)),
		0)
	if r == 0 {
		return 0, e2
	}
	return int(n), nil
}

// Size returns the console's visible window size in character cells.  This is
// the viewport, not the screen buffer: with scrollback the buffer is far taller
// than what the user can see, and the remote terminal must match the viewport.
func (c *Console) Size() (cols, rows int, ok bool) {
	if cols, rows, ok := c.sizeOf(c.out); ok {
		return cols, rows, true
	}
	// stdout may be redirected to a file or pipe while the process is still
	// attached to a console -- "winsh host cmd > out.txt" -- and the geometry
	// the far side is told about should still be the real window.  Opening
	// CONOUT$ reaches the screen buffer regardless of the standard handles.
	return c.sizeOfConsoleBuffer()
}

func (c *Console) sizeOf(h syscall.Handle) (cols, rows int, ok bool) {
	if h == 0 || h == syscall.InvalidHandle {
		return 0, 0, false
	}
	var info consoleScreenBufferInfo
	r, _, _ := procGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return 0, 0, false
	}
	cols = int(info.window.Right-info.window.Left) + 1
	rows = int(info.window.Bottom-info.window.Top) + 1
	if cols < 1 || rows < 1 {
		return 0, 0, false
	}
	return cols, rows, true
}

func (c *Console) sizeOfConsoleBuffer() (cols, rows int, ok bool) {
	name, err := syscall.UTF16PtrFromString("CONOUT$")
	if err != nil {
		return 0, 0, false
	}
	h, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(name)),
		genericRead|genericWrite,
		fileShareReadWrite,
		0, openExisting, 0, 0)
	if h == 0 || h == uintptr(syscall.InvalidHandle) {
		return 0, 0, false
	}
	defer syscall.CloseHandle(syscall.Handle(h))
	return c.sizeOf(syscall.Handle(h))
}

// ReadEvents blocks for console input records.  When stdin is not a console it
// reads bytes from os.Stdin instead and returns them as a single synthetic
// event, so that piping input still works (and so that winsh is testable).
func (c *Console) ReadEvents() ([]Event, error) {
	if !c.stdinIsConsole {
		buf := make([]byte, 4096)
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			return []Event{{Kind: "raw", Bytes: buf[:n]}}, nil
		}
		if err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	records := make([]inputRecord, 64)
	var nread uint32
	r, _, err := procReadConsoleInputW.Call(
		uintptr(c.in),
		uintptr(unsafe.Pointer(&records[0])),
		uintptr(len(records)),
		uintptr(unsafe.Pointer(&nread)))
	if r == 0 {
		return nil, err
	}
	out := make([]Event, 0, nread)
	for _, rec := range records[:nread] {
		switch rec.EventType {
		case keyEventRecord:
			k := rec.key()
			if !k.KeyDown {
				continue
			}
			out = append(out, Event{Kind: "key", Key: k})
		case windowBufferSizeEvent:
			// The record carries the *screen buffer* dimensions, and the
			// buffer is not the viewport: with scrollback the buffer is far
			// taller than the window, and dragging the window edge or changing
			// the font can leave the buffer untouched.  The remote terminal has
			// to match what the user can actually see, so re-query the window
			// rect instead of trusting the event payload.
			if cols, rows, ok := c.Size(); ok {
				out = append(out, Event{Kind: "resize", Cols: cols, Rows: rows})
			}
		}
	}
	return out, nil
}

type inputRecord struct {
	EventType uint16
	// INPUT_RECORD is WORD EventType followed by a union.  The union has to be
	// 4-byte aligned (KEY_EVENT_RECORD ends in a DWORD), so two bytes of
	// padding sit between them and the payload starts at offset 4.  The union
	// is 16 bytes, making the whole record exactly 20 bytes.  ReadConsoleInputW
	// writes records back-to-back at this ABI size; declaring a larger Go
	// struct makes every record after the first decode from the wrong offset.
	_    uint16
	data [16]byte
}

func (r *inputRecord) key() KeyEvent {
	// KEY_EVENT_RECORD, byte for byte as wincon.h declares it and as verified
	// against a capture from ReadConsoleInputW:
	//
	//	+0  BOOLEAN bKeyDown          -- one byte, not a WORD
	//	+1  (three bytes of padding, because the struct has to be 4-aligned
	//	     for the DWORD at the end)
	//	+4  WORD    wRepeatCount
	//	+6  WORD    wVirtualKeyCode
	//	+8  WORD    wVirtualScanCode
	//	+10 WCHAR   UnicodeChar
	//	+12 DWORD   dwControlKeyState
	//
	// Reading bKeyDown as a WORD shifts everything after it by two bytes, and
	// the result looks superficially plausible.  Measured on the Ctrl-Shift-6
	// record pinned in console_windows_test.go: the repeat count arrives as the
	// virtual-key code (0x01 instead of 0x36), the scan code arrives as the
	// character (0x07 instead of the 0x1E that is the escape key), and the
	// character's own bits land in the control-key state (0xc001e), which turns
	// on the right-alt bit -- so every keystroke went out ESC-prefixed as a
	// control byte nobody pressed.  bKeyDown is also what tells key up from key
	// down, so a shift here breaks the filter that stops released keys echoing.
	kb := r.data[0]
	rep := uint16(r.data[4]) | uint16(r.data[5])<<8
	vk := uint16(r.data[6]) | uint16(r.data[7])<<8
	// bytes 8 and 9 are the scan code, which is not needed here.
	ch := uint16(r.data[10]) | uint16(r.data[11])<<8
	state := uint32(r.data[12]) | uint32(r.data[13])<<8 | uint32(r.data[14])<<16 | uint32(r.data[15])<<24
	return KeyEvent{
		KeyDown:      kb != 0,
		RepeatCount:  rep,
		VirtualKey:   vk,
		CharCode:     ch,
		VirtualState: state,
	}
}

func (r *inputRecord) size() coord {
	return coord{
		X: int16(uint16(r.data[0]) | uint16(r.data[1])<<8),
		Y: int16(uint16(r.data[2]) | uint16(r.data[3])<<8),
	}
}

// procWriteFile is declared separately so the block above stays readable.
var procWriteFile = kernel32.NewProc("WriteFile")

// ---------- console control events ----------

var (
	ctrlCallbacks []func()
	ctrlOnce      sync.Once
)

// InstallCtrlHandler arranges for the console modes to be restored if the
// process is killed by Ctrl-C, Ctrl-Break, a window close, or a logoff.
// Without this, a killed client leaves the user's terminal in raw mode.
func InstallCtrlHandler(onExit func()) {
	if onExit != nil {
		ctrlCallbacks = append(ctrlCallbacks, onExit)
	}
	ctrlOnce.Do(func() {
		cb := syscall.NewCallback(func(ctrlType uint32) uintptr {
			for _, f := range ctrlCallbacks {
				f()
			}
			return 0 // not handled: let the default action terminate the process
		})
		procSetConsoleCtrlHandler.Call(cb, 1)
	})
}

// InstallRestoreOnExit arranges for the console modes to be restored if the
// process is terminated abnormally.
func (c *Console) InstallRestoreOnExit() {
	InstallCtrlHandler(func() { c.Restore() })
}

// ReadLineNoEcho reads one line without echoing it, for password prompts.
// When stdin is not a console it falls back to plain line reading.
func (c *Console) ReadLineNoEcho() (string, error) {
	if c == nil || !c.stdinIsConsole {
		var s string
		_, err := fmt.Fscanln(os.Stdin, &s)
		return s, err
	}
	// Turn echo off for the duration of the read.
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(uintptr(c.in), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return "", winError("GetConsoleMode", nil)
	}
	noEcho := mode & ^uint32(enableEchoInput|enableLineInput)
	if r, _, _ := procSetConsoleMode.Call(uintptr(c.in), uintptr(noEcho)); r == 0 {
		return "", winError("SetConsoleMode", nil)
	}
	defer procSetConsoleMode.Call(uintptr(c.in), uintptr(mode))

	var out []rune
	records := make([]inputRecord, 32)
	for {
		var nread uint32
		r, _, err := procReadConsoleInputW.Call(
			uintptr(c.in),
			uintptr(unsafe.Pointer(&records[0])),
			uintptr(len(records)),
			uintptr(unsafe.Pointer(&nread)))
		if r == 0 {
			return string(out), err
		}
		for _, rec := range records[:nread] {
			if rec.EventType != keyEventRecord {
				continue
			}
			k := rec.key()
			if !k.KeyDown {
				continue
			}
			switch {
			case k.VirtualKey == vkReturnLocal:
				fmt.Fprint(os.Stderr, "\r\n")
				return string(out), nil
			case k.VirtualKey == vkEscapeLocal:
				fmt.Fprint(os.Stderr, "\r\n")
				return "", errors.New("consoleapi: cancelled")
			case k.VirtualKey == vkBackspaceLocal:
				if len(out) > 0 {
					out = out[:len(out)-1]
				}
			case k.CharCode >= 0x20 && k.CharCode < 0x7F:
				out = append(out, rune(k.CharCode))
				fmt.Fprint(os.Stderr, "*")
			}
		}
	}
}

// Local virtual-key codes needed by ReadLineNoEcho.
const (
	vkReturnLocal    = 0x0D
	vkEscapeLocal    = 0x1B
	vkBackspaceLocal = 0x08
)
