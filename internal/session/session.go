// Package session is the interactive client: it drives the transport, the
// terminal emulator, the console, and the mosh control keys from one loop.
//
// The loop deliberately stays single-threaded apart from the two I/O goroutines
// (console input and UDP reads), because the cipher session, the replay window,
// and the SSP state windows are all single-goroutine by design.
package session

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"winsh/internal/consoleapi"
	"winsh/internal/predict"
	"winsh/internal/state"
	"winsh/internal/stream"
	"winsh/internal/transport"
	"winsh/internal/vt"
)

// Prediction modes, matching mosh's --predict.
const (
	PredictAdaptive     = "adaptive"
	PredictAlways       = "always"
	PredictNever        = "never"
	PredictExperimental = "experimental"
)

// Defaults taken from the reference client's behaviour.
const (
	DefaultEscapeKey    = 0x1E // Ctrl-^
	connectNotification = 30 * time.Second
	connectPoll         = 250 * time.Millisecond
	// idlePoll is how long the loop blocks when the sender has nothing
	// scheduled; input and network events wake it sooner.
	idlePoll         = 250 * time.Millisecond
	maxPendingEvents = 128
)

// Options configures a Client.
type Options struct {
	// Predict is one of the Predict* constants.
	Predict string
	// PredictOverwrite makes predicted input overwrite rather than insert.
	PredictOverwrite bool
	// Verbose writes per-packet diagnostics to stderr.
	Verbose bool
	// NoTermInit suppresses the terminal-initialisation string, matching
	// mosh's --no-init / MOSH_NO_TERM_INIT.
	NoTermInit bool
	// TitlePrefix is prepended to the window title; mosh uses "[mosh] ".
	TitlePrefix string
	// EscapeKey is the byte that introduces the control sequence, or -1 to
	// disable it.
	EscapeKey int
	// ConnectTimeout bounds the wait for the first server packet.  Zero uses
	// the 15-second reference behaviour.
	ConnectTimeout time.Duration
	// IdleTimeout exits the session after this long without user input
	// (mosh's --shutdown-after-idle).
	IdleTimeout time.Duration
	// ServerTimeout exits if the server is silent this long.  Zero means wait
	// indefinitely, as mosh does.
	ServerTimeout time.Duration
	// ServerPort and ServerHost are only used in user-facing messages.
	// HaveRemoteCommand says the client was asked to run a one-shot command
	// rather than open an interactive shell, which changes what a silent
	// server means: for a command it means the command finished and
	// mosh-server has exited.
	HaveRemoteCommand bool
	ServerHost        string
	ServerPort        int
}

// Client runs one interactive session.
type Client struct {
	opt Options
	con *consoleapi.Console
	tr  *transport.Transport
	enc KeyEncoder

	cols, rows int
	// local is what the console currently displays; frame diffs are computed
	// against it.
	local *vt.Screen
	// repaint forces a full redraw, as Ctrl-L and a resize do.
	repaint bool

	pred *predict.Engine

	notif       string
	notifSticky bool
	notifUntil  time.Time
	netErr      string

	escapePending bool
	lfEntered     bool

	started   time.Time
	connected bool
	cleanExit bool
	quitting  bool

	lastInput time.Time

	running bool
	// lastErr keeps the most recent transport error for diagnostics.
	lastErr string

	events chan consoleapi.Event
	stop   chan struct{}
	wg     sync.WaitGroup
	closed bool

	// MaxLoopIterations bounds the loop for tests; zero means run forever.
	MaxLoopIterations int

	// lastNum/haveLast record the most recently painted server state, and
	// lastNotif the notification drawn with it, so render can skip work when
	// none of them moved.
	lastNum   uint64
	haveLast  bool
	lastNotif string
	lastPred  uint64
	// lastSizeCheck paces the console-geometry poll in pollSize.
	lastSizeCheck time.Time
	// quitAt stamps when the user asked to leave, so the loop can give up
	// on the shutdown handshake by the clock rather than trusting the
	// sender's acknowledgment bookkeeping.
	quitAt time.Time
	cycleN int
	// firstQuitCycle is the loop pass on which quitting was first observed.
	quitPasses int
}

// New returns a client for an established transport.  con may be nil, which
// runs headless (used by the test suite and by piped input).
func New(con *consoleapi.Console, tr *transport.Transport, cols, rows int, opt Options) *Client {
	if opt.Predict == "" {
		opt.Predict = PredictAdaptive
	}
	if opt.EscapeKey == 0 {
		opt.EscapeKey = DefaultEscapeKey
	}
	if cols < 1 {
		cols = 80
	}
	if rows < 1 {
		rows = 24
	}
	c := &Client{
		opt:   opt,
		con:   con,
		tr:    tr,
		cols:  cols,
		rows:  rows,
		local: vt.NewScreen(cols, rows),
		pred: predict.New(predict.Options{
			Mode:      predict.ParseMode(opt.Predict),
			Overwrite: opt.PredictOverwrite,
		}),
		started:   time.Now(),
		lastInput: time.Now(),
		events:    make(chan consoleapi.Event, maxPendingEvents),
		stop:      make(chan struct{}),
	}
	// mosh puts the real local terminal in application-cursor-key mode and
	// expects its server-side terminal parser to translate SS3 A-D back to
	// CSI A-D when the remote application has not enabled DECCKM.  The
	// Windows console is a byte source here, so winsh has to make the same
	// choice explicitly.  Do not drive this from the rendered remote screen:
	// DECCKM is server-side parser state and mosh's frame diff does not carry
	// it back to the client.
	c.enc.SetApplicationCursor(true)
	return c
}

// PushInput injects bytes as if the user had typed them.  It is the entry
// point for piped stdin and for tests.
func (c *Client) PushInput(b []byte) {
	select {
	case c.events <- consoleapi.Event{Kind: "raw", Bytes: b}:
	case <-c.stop:
	}
}

// PushResize injects a window-size change.
func (c *Client) PushResize(cols, rows int) {
	select {
	case c.events <- consoleapi.Event{Kind: "resize", Cols: cols, Rows: rows}:
	case <-c.stop:
	}
}

func (c *Client) emit(s string) { c.emitBytes([]byte(s)) }

func (c *Client) emitBytes(b []byte) {
	if c.con == nil {
		return
	}
	if _, err := c.con.Write(b); err != nil && c.opt.Verbose {
		fmt.Fprintf(os.Stderr, "winsh: console write: %v\n", err)
	}
}

func (c *Client) startConsoleReader() {
	if c.con == nil {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			evs, err := c.con.ReadEvents()
			if err != nil {
				return
			}
			for _, e := range evs {
				select {
				case c.events <- e:
				case <-c.stop:
					return
				}
			}
		}
	}()
}

// Stop ends the run loop and releases the console reader.
func (c *Client) Stop() {
	if c.closed {
		return
	}
	c.closed = true
	close(c.stop)
	// The console reader goroutine is parked inside ReadConsoleInputW, which
	// returns only when input arrives -- and someone calling Stop has usually
	// just decided to leave, so no input is coming.  Waiting for it turns
	// shutdown into a hang, so give the goroutine a moment and then abandon it;
	// the process is on its way out and the OS reclaims the thread.
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
	}
	if c.con != nil {
		c.con.Restore()
	}
}

// Run drives the session until it ends.  It returns nil for a clean shutdown.
func (c *Client) Run() error {
	if c.con != nil {
		if err := c.con.EnterRaw(); err != nil && c.opt.Verbose {
			fmt.Fprintf(os.Stderr, "winsh: console mode: %v\n", err)
		}
		c.startConsoleReader()
		defer c.con.Restore()
	}
	if !c.opt.NoTermInit {
		// Take over the user's terminal: alternate screen, clear, and let the
		// per-frame renderer decide cursor visibility.  The SGR reset matters:
		// the frame renderer assumes each frame starts from the default pen, and
		// switching to the alternate screen does not clear what the user's shell
		// left behind.
		c.emit("\x1b[?1049h\x1b[0m\x1b[2J\x1b[H")
	}
	defer func() {
		if !c.opt.NoTermInit {
			c.emit("\x1b[?1049l\x1b[0m\x1b[?25h")
		}
	}()

	// Announce the initial window size so the server matches it.
	c.tr.Sender.Push(func(s stream.State) { s.(*state.UserStream).PushResize(c.cols, c.rows) })

	c.running = true
	defer func() { c.running = false }()
	iterations := 0
	for {
		if c.MaxLoopIterations > 0 && iterations >= c.MaxLoopIterations {
			return nil
		}
		iterations++
		c.cycleN++
		// The quit deadline is enforced here, in the loop itself, rather than
		// inside cycle(): measured against a stamp taken in beginExit it never
		// elapsed, and a counter kept here cannot be reset or starved by
		// anything further down.  One pass is ~20ms, so 100 passes is about two
		// seconds of re-offering the shutdown instruction -- plenty for a
		// healthy link, and bounded on a dead one.
		if c.quitting {
			if c.tr.Sender.ShutdownAcknowledged() {
				c.cleanExit = true
				return nil
			}
			c.quitPasses++
			if c.quitPasses >= shutdownMaxPasses || c.tr.Sender.ShutdownAckTimedOut() {
				if c.opt.Verbose {
					fmt.Fprintf(os.Stderr, "winsh: shutdown unacknowledged after %d passes; handing the terminal back\n",
						c.quitPasses)
				}
				c.cleanExit = true
				return nil
			}
		}
		// The other side is gone: mosh-server starts its own graceful shutdown
		// when the user's shell exits, and once we have answered that instruction
		// with an acknowledgment of our own there is nothing left to wait for.
		// This is mosh's counterparty_shutdown_ack_sent test (stmclient.cc).
		//
		// It belongs here, in the loop that owns the session, and not in cycle():
		// cycle returns nil both for "keep going" and for "we are finished", and
		// Run only stops on a non-nil error, so a clean exit requested from
		// inside cycle was indistinguishable from an ordinary pass.  That is why
		// typing exit at a shell prompt used to leave the terminal attached to a
		// dead session forever.
		if c.tr.Sender.CounterpartyShutdownAcknowledged() {
			c.cleanExit = true
			return nil
		}
		if err := c.cycle(); err != nil {
			return err
		}
	}
}

// cycle performs one pass of the event loop.
func (c *Client) cycle() error {
	// 1. Take everything the network has delivered.
	if _, err := c.tr.Drain(); err != nil {
		if errors.Is(err, transport.ErrProtocol) {
			c.setNetworkError(err.Error())
		} else {
			return err
		}
	}
	if n := c.tr.Conn.LastHeard(); !n.IsZero() && !c.connected {
		c.connected = true
		c.clearNotification()
		c.maybeShowConnectHint()
	}

	// 2. Service the send timers.
	if err := c.tr.Tick(); err != nil {
		c.setNetworkError(err.Error())
	}
	if msg := c.tr.Conn.SendError(); msg != "" {
		c.lastErr = msg
		c.setNetworkError(msg)
	}

	// 3. Reconcile speculative input with the authoritative server state.
	c.observePredictions()

	// 4. Notice a window resize, then repaint.
	c.pollSize()
	c.expireNotification(time.Now())
	c.render(false)

	// 5. Lifecycle checks.
	if err := c.checkDeadlines(); err != nil {
		return err
	}
	// The end-of-session decisions for a shutdown -- ours or the server's -- are
	// made by Run, which is the only place a return actually ends the session.

	// 6. Wait for the next event.
	wait := c.nextWait()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case ev, ok := <-c.events:
		if !ok {
			return nil
		}
		c.handleEvent(ev)
	case <-c.tr.Conn.DataReady():
		// A datagram landed.  Nothing to do here: the next cycle drains the
		// queue at the top of the loop.  Without this case the loop would
		// only notice replies when a timer happened to expire.
	case <-timer.C:
	case <-c.stop:
		return nil
	}
	return nil
}

// nextWait decides how long the event loop may block.  Getting this wrong is
// not a cosmetic bug: the sender's "nothing scheduled" and "due right now"
// results both used to arrive here as a non-positive number and were turned
// into a one-second sleep, which pinned the whole session to roughly 1 Hz
// instead of mosh's 20-250 ms frame rate.
func (c *Client) nextWait() time.Duration {
	w := c.tr.WaitTime(-1)
	switch {
	case w == 0:
		// Due now.  Yield briefly so the loop cannot starve the reader
		// goroutines, but do not sleep.
		w = time.Millisecond
	case w < 0:
		// Nothing scheduled.  Keystrokes and datagrams both arrive over
		// channels that wake the select, so this only gates background
		// work such as the notification and timeout checks.
		w = idlePoll
	}
	if !c.connected && w > connectPoll {
		w = connectPoll
	}
	if w > time.Second {
		w = time.Second
	}
	if pw := c.pred.WaitTime(); pw > 0 && pw < w {
		w = pw
	}
	return w
}

func (c *Client) checkDeadlines() error {
	now := time.Now()
	if !c.connected {
		limit := c.opt.ConnectTimeout
		if limit <= 0 {
			limit = connectNotification
		}
		if now.Sub(c.started) > limit {
			return fmt.Errorf(
				"winsh: no successful connection to %s:%d on UDP.\n"+
					"Please verify that UDP port %d is not firewalled and can reach the server.\n"+
					"(The -p option selects the server's UDP port.)",
				c.opt.ServerHost, c.opt.ServerPort, c.opt.ServerPort)
		}
		if now.Sub(c.started) > 2*time.Second && c.notif == "" {
			c.setNotification(fmt.Sprintf("Nothing received from server on UDP port %d.", c.opt.ServerPort), true)
		}
	}
	// "winsh host command" has to end when the command ends.  mosh-server has no
	// goodbye that can be relied on to arrive, but a live server always answers
	// the empty acknowledgements the client sends every few seconds.  Silence
	// for this long therefore means the server is gone -- which for a one-shot
	// command is the normal, successful ending, and the case that used to leave
	// the client sitting there until it was killed.  Starting the shutdown here
	// means a late acknowledgement still counts as a clean finish.
	if c.opt.HaveRemoteCommand && c.connected && !c.quitting {
		if last := c.tr.Conn.LastHeard(); !last.IsZero() && now.Sub(last) >= CommandIdleExit {
			c.beginExit("")
		}
	}
	if c.opt.ServerTimeout > 0 && c.connected {
		if last := c.tr.Conn.LastHeard(); !last.IsZero() && now.Sub(last) > c.opt.ServerTimeout {
			return fmt.Errorf("winsh: no response from server for %v", c.opt.ServerTimeout)
		}
	}
	if c.opt.IdleTimeout > 0 && !c.quitting && now.Sub(c.lastInput) > c.opt.IdleTimeout {
		c.beginExit("Idle timeout, exiting...")
	}
	return nil
}

// render repaints the console from the newest server state.
func (c *Client) render(force bool) {
	st, num, err := c.tr.LatestRemote()
	if err != nil {
		return
	}
	ts, ok := st.(*vt.TerminalState)
	if !ok {
		return
	}
	predVersion := c.pred.Version()
	// Only repaint when something could have changed.  Without this the loop
	// re-emitted the cursor positioning on every pass, which once the send
	// timers were honoured (rather than being throttled by a stray one-second
	// sleep) turned into tens of thousands of no-op escape sequences a minute
	// and well over a megabyte of console traffic for an idle screen.
	if !force && !c.repaint && predVersion == c.lastPred &&
		c.notif == c.lastNotif && c.haveLast && num == c.lastNum {
		return
	}
	term := c.pred.Render(ts.Term)
	if term == nil {
		return
	}
	if c.notif != "" {
		c.paintNotification(term)
	}
	x, y, visible := term.Cursor()
	tx, ty := x, y
	if !visible {
		tx, ty = -1, -1
	}
	title := ""
	if ti, has := term.Title(); has {
		title = c.opt.TitlePrefix + ti
	}
	frame := vt.RenderFrame(c.local, term.Screen(), tx, ty, visible, vt.RenderOptions{
		Differential: !force && !c.repaint,
		Title:        title,
	})
	if len(frame) > 0 {
		c.emitBytes(frame)
	}
	c.local = term.Screen().Clone()
	c.repaint = false
	c.lastNum, c.haveLast, c.lastNotif = num, true, c.notif
	c.lastPred = predVersion
}

// paintNotification draws the current notice across the bottom row, matching
// the reference client's habit of using the last line for session messages.
func (c *Client) paintNotification(term *vt.Terminal) {
	scr := term.Screen()
	if scr.Rows < 1 {
		return
	}
	pen := vt.Cell{Raw: ' ', Attr: vt.AttrReverse}
	y := scr.Rows - 1
	text := " " + c.notif + " "
	x := 0
	for _, r := range text {
		if x >= scr.Cols {
			break
		}
		cell := pen
		cell.Raw = r
		scr.Set(x, y, cell)
		x++
	}
	for ; x < scr.Cols; x++ {
		scr.Set(x, y, pen)
	}
}

// observePredictions feeds the latest authoritative screen and acknowledgment
// counters to the prediction engine.  EchoAck is the server's delayed
// confirmation that input reached the pty; SentStateAcked is the SSP-level
// fallback for peers that do not send it.
func (c *Client) observePredictions() {
	st, _, err := c.tr.LatestRemote()
	if err != nil {
		return
	}
	ts, ok := st.(*vt.TerminalState)
	if !ok {
		return
	}
	c.pred.Observe(ts.Term, ts.EchoAck, c.tr.Sender.SentStateAcked(),
		c.tr.Sender.SendInterval(), time.Now())
}

func (c *Client) handleEvent(ev consoleapi.Event) {
	switch ev.Kind {
	case "key":
		b := c.enc.Encode(ev.Key)
		if len(b) > 0 {
			c.handleBytes(b)
		}
	case "raw":
		c.handleBytes(ev.Bytes)
	case "resize":
		c.handleResize(ev.Cols, ev.Rows)
	}
}

// sizePollInterval bounds how often the loop re-queries the console geometry.
// The syscall is cheap, but there is no reason to make it every pass.
const sizePollInterval = 125 * time.Millisecond

// shutdownDeadline is the hard cap on the graceful-shutdown exchange.  mosh
// keeps asking for ACTIVE_RETRY_TIMEOUT, which leaves the terminal frozen on
// "Exiting..." when the last reply is lost; the user asked to leave, so after
// this long we hand the console back.  The server reaps the orphan itself.
const shutdownDeadline = 2 * time.Second

// shutdownMaxPasses is the pass-count equivalent of shutdownDeadline, used
// because it is measured where the loop actually is.  At the ~50 Hz this loop
// runs at, 50 passes is about a second: long enough for a live server to
// acknowledge the shutdown it was asked for, short enough that a server which
// is already gone does not cost the user another two seconds of frozen
// terminal.
const shutdownMaxPasses = 50

// CommandIdleExit is how long the client waits for a one-shot command's server
// to answer an acknowledgement before concluding the command finished and
// mosh-server exited.  Exported so tests and --diagnostics can reason about the
// session's timing without duplicating the number.
const CommandIdleExit = 3 * time.Second

// pollSize notices a window resize that produced no console event at all.
//
// Windows only guarantees WINDOW_BUFFER_SIZE_EVENT when the *buffer* changes.
// Dragging the window edge, maximising, going full screen, or changing the
// console font can all leave the buffer alone, so a client that waits for the
// event keeps telling the server about the size the window happened to have
// when the session started -- which is indistinguishable from "it ignores my
// window size".  Asking the console directly is the only reliable source.
func (c *Client) pollSize() {
	if c.con == nil {
		return
	}
	now := time.Now()
	if !c.lastSizeCheck.IsZero() && now.Sub(c.lastSizeCheck) < sizePollInterval {
		return
	}
	c.lastSizeCheck = now
	cols, rows, ok := c.con.Size()
	if !ok {
		return
	}
	c.handleResize(cols, rows)
}

func (c *Client) handleResize(cols, rows int) {
	if cols < 1 || rows < 1 {
		return
	}
	if cols == c.cols && rows == c.rows {
		return
	}
	c.cols, c.rows = cols, rows
	c.tr.Sender.Push(func(s stream.State) { s.(*state.UserStream).PushResize(cols, rows) })
	c.pred.Reset()
	c.repaint = true
	c.local = vt.NewScreen(cols, rows)
}

// pushInput appends bytes to the user stream and, when prediction is on,
// echoes them locally.
func (c *Client) pushInput(b []byte) {
	now := time.Now()
	frame := c.tr.Sender.SentStateLast() + 1
	c.tr.Sender.Push(func(s stream.State) { s.(*state.UserStream).PushBytes(b) })
	st, _, err := c.tr.LatestRemote()
	if err == nil {
		if ts, ok := st.(*vt.TerminalState); ok {
			c.pred.AddInput(b, ts.Term, frame, now)
		}
	}
	c.lastInput = now
}

// handleBytes implements mosh's control-key grammar: the escape key introduces
// a short sequence, and while it is pending the next byte chooses an action.
func (c *Client) handleBytes(b []byte) {
	paste := len(b) > 100
	if paste {
		// A paste is not worth predicting: guessing wrong on hundreds of
		// characters is worse than waiting for the server's echo.
		c.pred.Reset()
	}
	for _, ch := range b {
		if c.escapePending {
			c.escapePending = false
			if c.notifSticky {
				c.clearNotification()
			}
			switch {
			case ch == '.':
				if c.tr.Conn.HasRemoteAddr() && !c.tr.Sender.ShutdownInProgress() {
					c.beginExit("Exiting on user request...")
					return
				}
				return
			case ch == 0x1A: // Ctrl-Z: the Windows analogue of suspend
				c.detach()
				return
			case ch == c.passKey(), ch == c.passKey2():
				c.pushInput([]byte{byte(c.opt.EscapeKey)})
			default:
				c.pushInput([]byte{byte(c.opt.EscapeKey), ch})
			}
			continue
		}
		// mosh decides whether the escape key must follow a newline by the kind
		// of key it is, not by luck: stmclient.cc sets escape_requires_lf false
		// when the escape is a control character and true only when it is a
		// printable one.  Requiring a newline for Ctrl-^ made the escape do
		// nothing unless the user happened to press Enter first -- the whole
		// "Ctrl-^ doesn't seem to work" complaint.
		if c.opt.EscapeKey > 0 && ch == byte(c.opt.EscapeKey) &&
			(c.lfEntered || c.opt.EscapeKey < 32) {
			c.escapePending = true
			c.lfEntered = false
			c.setNotification(c.escapeHelp(), true)
			continue
		}
		c.lfEntered = ch == '\n' || ch == '\r'
		if ch == 0x0C { // Ctrl-L
			c.repaint = true
		}
		c.pushInput([]byte{ch})
	}
}

func (c *Client) passKey() byte {
	k := byte(c.opt.EscapeKey)
	if k < 32 {
		k += '@'
	}
	return k
}

func (c *Client) passKey2() byte {
	k := c.passKey()
	if k >= 'A' && k <= 'Z' {
		return k + ('a' - 'A')
	}
	return k
}

// escapeKeyName spells the escape key the way mosh spells it: "Ctrl-^" for a
// control escape, and a quoted character for a printable one.  Showing the raw
// byte instead produced the helpful notification "gives literal \"\\x1e\"", which
// told the user nothing.
func (c *Client) escapeKeyName() string {
	if c.opt.EscapeKey < 32 {
		return "Ctrl-" + string(c.passKey())
	}
	return "\"" + string(byte(c.opt.EscapeKey)) + "\""
}

func (c *Client) escapeHelp() string {
	return fmt.Sprintf("Commands: Ctrl-Z detaches, \".\" quits, \"%c\" gives literal %s",
		c.passKey(), c.escapeKeyName())
}

// beginExit starts the graceful shutdown exchange.
func (c *Client) beginExit(msg string) {
	if c.quitting {
		return
	}
	c.quitting = true
	c.quitAt = time.Now()
	c.setNotification(msg, true)
	c.tr.Sender.StartShutdown()
}

// detach restores the user's terminal and re-dials the socket, then waits for
// Enter.  Windows has no job control, so this is the closest equivalent to
// mosh's Ctrl-Z suspend: the server keeps running and the session resumes with
// a fresh UDP 5-tuple.
func (c *Client) detach() {
	if c.con != nil {
		c.con.Restore()
	}
	c.emitBytes([]byte("\r\n[winsh is detached.]\r\nPress Enter to reconnect...\r\n"))
	if err := c.tr.Conn.Redial(); err != nil && c.opt.Verbose {
		fmt.Fprintf(os.Stderr, "winsh: redial: %v\n", err)
	}
	// Drain queued events, then block for a line of input.
	for {
		select {
		case <-c.events:
			continue
		default:
		}
		break
	}
	deadline := time.After(30 * time.Second)
	for {
		select {
		case ev := <-c.events:
			if ev.Kind == "raw" && (containsByte(ev.Bytes, '\n') || containsByte(ev.Bytes, '\r')) {
				c.reattach()
				return
			}
			if ev.Kind == "key" && ev.Key.VirtualKey == vkReturn {
				c.reattach()
				return
			}
		case <-deadline:
			c.reattach()
			return
		case <-c.stop:
			return
		}
	}
}

func (c *Client) reattach() {
	// The server may have been idle; ask it to re-send by resizing to the same
	// size, which creates a new state and therefore a fresh frame.
	c.repaint = true
	c.pred.Reset()
	c.local = vt.NewScreen(c.cols, c.rows)
	c.tr.Sender.Push(func(s stream.State) { s.(*state.UserStream).PushResize(c.cols, c.rows) })
	if c.con != nil {
		if err := c.con.EnterRaw(); err == nil {
			c.emit("\x1b[?1049h\x1b[0m\x1b[2J\x1b[H")
		}
	}
}

func containsByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

func (c *Client) setNotification(s string, sticky bool) {
	c.notif = s
	c.notifSticky = sticky
	if !sticky {
		c.notifUntil = time.Now().Add(4 * time.Second)
	}
	c.repaint = true
}

// maybeShowConnectHint puts the escape-key grammar on the bottom row the first
// time the server is heard from.  Nothing else in the product tells a first-time
// user how to leave, and the key is Ctrl+Shift+6 -- nobody guesses that.  It is a
// notice, not program output: it is painted locally only, never sent to the
// server, never part of the remote screen a --dump-screen prints, it is not shown
// for a one-shot remote command or a piped stdin, and it clears itself like any
// other transient notice.
func (c *Client) maybeShowConnectHint() {
	if c.opt.HaveRemoteCommand || c.opt.EscapeKey <= 0 {
		return
	}
	if c.con != nil && !c.con.InputIsConsole() {
		return
	}
	name := c.escapeKeyName()
	c.setNotification(fmt.Sprintf(
		"%s then \".\" quits; %s Ctrl-Z detaches (--help lists the commands)", name, name), false)
}

// expireNotification retires a notice that was asked to be transient.  Without
// this the expiry time setNotification records was never read, so a one-off
// "Network error" stayed on the bottom row for the rest of the session.
func (c *Client) expireNotification(now time.Time) {
	if c.notif == "" || c.notifSticky || c.notifUntil.IsZero() {
		return
	}
	if now.After(c.notifUntil) {
		c.clearNotification()
	}
}

func (c *Client) clearNotification() {
	if c.notif != "" {
		c.notif = ""
		c.notifSticky = false
		c.repaint = true
	}
}

func (c *Client) setNetworkError(msg string) {
	c.netErr = msg
	c.setNotification("Network error: "+msg, false)
}

// QuitRequested reports that the user asked the session to end and the
// graceful-shutdown exchange is under way.
func (c *Client) QuitRequested() bool { return c.quitting }

// Running reports whether the event loop is currently turning.  Input pushed
// after it has stopped is discarded rather than queued behind a loop that will
// never read it again, so callers and tests can tell the two apart.
func (c *Client) Running() bool { return c.running }

// LastTransportError returns the most recent send-side failure, which is
// normally what explains a session that went quiet without ending: the
// connection keeps running after an ICMP error, so Run() returns nil and the
// reason would otherwise be lost.
func (c *Client) LastTransportError() string { return c.lastErr }

// Redial starts sending from a fresh local UDP port while keeping every bit of
// session state, including the sequence-number counter.  This is what roaming
// looks like from the client side, and it is also what the detach command
// uses.
func (c *Client) Redial() error { return c.tr.Conn.Redial() }

// LastRenderedText returns the console's current screen as text, used by
// diagnostics and tests.
func (c *Client) LastRenderedText() (string, error) {
	if c.local == nil {
		return "", errors.New("session: nothing rendered yet")
	}
	var b strings.Builder
	for y := 0; y < c.local.Rows; y++ {
		if y > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(c.local.RowString(y))
	}
	return b.String(), nil
}

// CleanExit reports whether the session ended with a proper shutdown exchange.
func (c *Client) CleanExit() bool { return c.cleanExit }

// LastRendered exposes the console's screen contents, used by diagnostics and
// the test suite.
func (c *Client) LastRendered() *vt.Screen { return c.local }

// DumpScreen renders the current server screen as text (--dump-screen).
func (c *Client) DumpScreen() ([]string, error) {
	st, _, err := c.tr.LatestRemote()
	if err != nil {
		return nil, err
	}
	ts, ok := st.(*vt.TerminalState)
	if !ok {
		return nil, errors.New("session: unexpected remote state type")
	}
	scr := ts.Term.Screen()
	out := make([]string, scr.Rows)
	for y := 0; y < scr.Rows; y++ {
		out[y] = scr.RowString(y)
	}
	return out, nil
}
