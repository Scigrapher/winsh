// Package predict implements speculative local echo for winsh.
//
// Predictions are sparse per-cell overlays over the authoritative server
// screen.  They are tied to the input state number that carried the keystroke
// and are retired only after the server acknowledges that input and the
// expected text is actually present.  A disagreement discards the speculative
// layer and lets the server screen win; it never becomes permanent local
// state.
package predict

import (
	"time"

	"winsh/internal/vt"
)

// Mode describes when predictions may be displayed.
type Mode uint8

const (
	ModeAdaptive Mode = iota
	ModeAlways
	ModeNever
	ModeExperimental
)

// ParseMode maps the command-line spelling to a prediction mode.
func ParseMode(s string) Mode {
	switch s {
	case "always":
		return ModeAlways
	case "never":
		return ModeNever
	case "experimental":
		return ModeExperimental
	default:
		return ModeAdaptive
	}
}

// Options configures a prediction engine.
type Options struct {
	Mode      Mode
	Overwrite bool
}

const (
	// Hysteresis for showing predictions and underlining outstanding ones.
	triggerLow  = 30 * time.Millisecond
	triggerHigh = 45 * time.Millisecond
	flagLow     = 50 * time.Millisecond
	flagHigh    = 80 * time.Millisecond

	glitchAfter    = 250 * time.Millisecond
	underlineAfter = 5 * time.Second
	repairGap      = 150 * time.Millisecond
	maxOriginals   = 4
	maxCursors     = 32
)

type cellPrediction struct {
	active      bool
	unknown     bool
	replacement vt.Cell
	frame       uint64
	epoch       uint64
	created     time.Time
	// originals records what occupied this position before the prediction.
	// Matching one of these is not evidence that the prediction was correct.
	originals []vt.Cell
}

type rowPrediction struct {
	cells []cellPrediction
}

type cursorPrediction struct {
	active  bool
	x, y    int
	frame   uint64
	epoch   uint64
	created time.Time
}

// Engine owns one session's speculative input layer.
type Engine struct {
	mode      Mode
	overwrite bool

	rows    map[int]*rowPrediction
	cursors []cursorPrediction

	epoch     uint64
	confirmed uint64

	x, y       int
	haveCursor bool

	parser inputParser

	sendInterval time.Duration
	showOnRTT    bool
	flagging     bool
	glitch       int
	lastQuick    time.Time

	width, height int
	version       uint64
	dirty         bool
}

// New returns an empty prediction engine.
func New(opts Options) *Engine {
	return &Engine{
		mode:      opts.Mode,
		overwrite: opts.Overwrite,
		rows:      make(map[int]*rowPrediction),
		epoch:     1,
	}
}

// SetPolicy updates the prediction policy without discarding pending input.
func (e *Engine) SetPolicy(mode Mode, overwrite bool) {
	if e.mode == mode && e.overwrite == overwrite {
		return
	}
	e.mode = mode
	e.overwrite = overwrite
	if mode == ModeNever {
		e.reset()
	}
	e.touch()
}

// Version changes whenever the visible prediction layer or its timing state
// changes.  The session uses it to avoid repainting unchanged frames.
func (e *Engine) Version() uint64 { return e.version }

// Pending reports whether any speculative input is still outstanding.
func (e *Engine) Pending() bool {
	for _, row := range e.rows {
		for i := range row.cells {
			if row.cells[i].active {
				return true
			}
		}
	}
	for i := range e.cursors {
		if e.cursors[i].active {
			return true
		}
	}
	return false
}

// WaitTime is the maximum time the event loop may sleep while predictions
// need timing work (glitch detection and underline expiry).
func (e *Engine) WaitTime() time.Duration {
	if e.Pending() {
		return 50 * time.Millisecond
	}
	return 0
}

// Reset discards every speculative cell and cursor.  The authoritative server
// screen remains untouched.
func (e *Engine) Reset() { e.reset() }

func (e *Engine) reset() {
	e.rows = make(map[int]*rowPrediction)
	e.cursors = nil
	e.haveCursor = false
	e.epoch++
	e.glitch = 0
	e.parser.reset()
	e.touch()
}

// AddInput records user bytes as speculative screen changes.  frame is the
// outgoing SSP state number that will carry these bytes.
func (e *Engine) AddInput(input []byte, base *vt.Terminal, frame uint64, now time.Time) {
	if e.mode == ModeNever || base == nil || len(input) == 0 {
		return
	}
	cols, rows := base.Geometry()
	if e.width != cols || e.height != rows {
		e.width, e.height = cols, rows
		e.reset()
	}
	if frame == 0 {
		frame = 1
	}
	if !e.haveCursor {
		e.x, e.y, _ = base.Cursor()
		e.haveCursor = true
	}

	// A large paste is not worth guessing; one wrong guess would be amplified
	// across hundreds of cells.
	if len(input) > 100 {
		e.reset()
		return
	}

	for _, ev := range e.parser.feed(input) {
		switch ev.kind {
		case eventRune:
			e.predictRune(base, ev.r, frame, now)
		case eventBackspace:
			e.predictBackspace(base, frame, now)
		case eventCarriageReturn, eventLineFeed:
			e.predictNewline(base, ev.kind == eventCarriageReturn, frame, now)
		case eventLeft:
			e.ensureCursor()
			if e.x > 0 {
				e.x--
				e.recordCursor(frame, now)
			}
		case eventRight:
			e.ensureCursor()
			if e.x < cols-1 {
				e.x++
				e.recordCursor(frame, now)
			}
		case eventUnsupported:
			e.beginEpoch()
		}
	}
	e.touch()
}

func (e *Engine) predictRune(base *vt.Terminal, r rune, frame uint64, now time.Time) {
	cols, rows := base.Geometry()
	if vt.RuneWidth(r) != 1 {
		e.beginEpoch()
		return
	}
	e.ensureCursor()
	if e.x < 0 || e.x >= cols || e.y < 0 || e.y >= rows {
		e.beginEpoch()
		return
	}

	row := e.row(e.y, cols)
	before := e.effective(base, row, e.x)
	if !e.overwrite {
		for x := cols - 1; x > e.x; x-- {
			src := e.effective(base, row, x-1)
			srcUnknown := e.effectiveUnknown(row, x-1)
			prior := e.effective(base, row, x)
			if !srcUnknown && !row.cells[x].active && isBlank(src) && isBlank(prior) {
				continue
			}
			e.put(row, x, src, srcUnknown, frame, now, prior)
		}
	}

	replacement := before
	replacement.Raw = r
	replacement.Comb = nil
	replacement.Wide = 0
	replacement.Attr &^= vt.AttrUnderline | vt.AttrDoubleUnderline
	e.put(row, e.x, replacement, false, frame, now, before)

	if e.x < cols-1 {
		e.x++
	} else {
		// Prediction in the final column is ambiguous: terminals may defer
		// wrapping, insert a marker, or scroll.  Keep the cell, but require
		// server confirmation before predicting more on that line.
		e.beginEpoch()
	}
	e.recordCursor(frame, now)
}

func (e *Engine) predictBackspace(base *vt.Terminal, frame uint64, now time.Time) {
	cols, _ := base.Geometry()
	e.ensureCursor()
	if e.x <= 0 {
		e.beginEpoch()
		return
	}
	e.x--
	row := e.row(e.y, cols)
	if e.overwrite {
		before := e.effective(base, row, e.x)
		blank := before
		blank.Raw = ' '
		blank.Comb = nil
		blank.Wide = 0
		e.put(row, e.x, blank, false, frame, now, before)
	} else {
		for x := e.x; x < cols-1; x++ {
			src := e.effective(base, row, x+1)
			srcUnknown := e.effectiveUnknown(row, x+1)
			prior := e.effective(base, row, x)
			if !srcUnknown && !row.cells[x].active && isBlank(src) && isBlank(prior) {
				continue
			}
			e.put(row, x, src, srcUnknown, frame, now, prior)
		}
		prior := e.effective(base, row, cols-1)
		if row.cells[cols-1].active || !isBlank(prior) {
			blank := prior
			blank.Raw = ' '
			blank.Comb = nil
			blank.Wide = 0
			e.put(row, cols-1, blank, true, frame, now, prior)
		}
	}
	e.recordCursor(frame, now)
}

func (e *Engine) predictNewline(base *vt.Terminal, carriageReturn bool, frame uint64, now time.Time) {
	cols, rows := base.Geometry()
	e.ensureCursor()
	e.beginEpoch()
	if carriageReturn {
		e.x = 0
	}
	if e.y < rows-1 {
		e.y++
	} else {
		// Bottom-line scrolling depends on the scroll region, which is
		// application state rather than something the input bytes reveal.
		e.reset()
		return
	}
	e.recordCursor(frame, now)
	_ = cols
}

func (e *Engine) ensureCursor() {
	if !e.haveCursor {
		e.x, e.y = 0, 0
		e.haveCursor = true
	}
}

func (e *Engine) beginEpoch() { e.epoch++ }

func (e *Engine) row(y, cols int) *rowPrediction {
	r := e.rows[y]
	if r == nil {
		r = &rowPrediction{cells: make([]cellPrediction, cols)}
		e.rows[y] = r
	} else if len(r.cells) != cols {
		n := make([]cellPrediction, cols)
		copy(n, r.cells)
		r.cells = n
	}
	return r
}

func (e *Engine) effective(base *vt.Terminal, row *rowPrediction, x int) vt.Cell {
	if x >= 0 && x < len(row.cells) {
		p := &row.cells[x]
		if p.active && !p.unknown {
			return p.replacement
		}
	}
	return base.Screen().At(x, e.y).Clone()
}

func (e *Engine) effectiveUnknown(row *rowPrediction, x int) bool {
	return x >= 0 && x < len(row.cells) && row.cells[x].active && row.cells[x].unknown
}

func (e *Engine) put(row *rowPrediction, x int, c vt.Cell, unknown bool, frame uint64, now time.Time, prior vt.Cell) {
	if x < 0 || x >= len(row.cells) {
		return
	}
	p := &row.cells[x]
	if !p.active {
		p.originals = p.originals[:0]
		p.created = now
	}
	p.active = true
	p.unknown = unknown
	p.replacement = c.Clone()
	p.frame = frame
	p.epoch = e.epoch
	p.created = now
	e.addOriginal(p, prior)
}

func (e *Engine) addOriginal(p *cellPrediction, c vt.Cell) {
	if len(p.originals) >= maxOriginals {
		return
	}
	for i := range p.originals {
		if sameContent(p.originals[i], c) {
			return
		}
	}
	p.originals = append(p.originals, c.Clone())
}

func (e *Engine) recordCursor(frame uint64, now time.Time) {
	if len(e.cursors) > 0 {
		c := &e.cursors[len(e.cursors)-1]
		if c.epoch == e.epoch {
			c.x, c.y = e.x, e.y
			c.frame, c.created, c.active = frame, now, true
			return
		}
	}
	e.cursors = append(e.cursors, cursorPrediction{
		active: true, x: e.x, y: e.y, frame: frame, epoch: e.epoch, created: now,
	})
	if len(e.cursors) > maxCursors {
		e.cursors = e.cursors[len(e.cursors)-maxCursors:]
	}
}

// Observe reconciles the speculative layer with a newer server state.  It must
// be called before Render each event-loop pass.
func (e *Engine) Observe(base *vt.Terminal, echoAck, senderAck uint64, interval time.Duration, now time.Time) {
	if base == nil || e.mode == ModeNever {
		return
	}
	cols, rows := base.Geometry()
	if e.width != cols || e.height != rows {
		e.width, e.height = cols, rows
		e.reset()
	}
	e.tune(interval)
	if !e.Pending() {
		return
	}

	for y, row := range e.rows {
		for x := range row.cells {
			p := &row.cells[x]
			if !p.active {
				continue
			}
			actual := base.Screen().At(x, y)

			// An acked input state whose expected cell is already present is
			// safe to retire even before the delayed echo-ack marker arrives.
			if senderAck >= p.frame && p.frame > 0 && !p.unknown && sameContent(actual, p.replacement) {
				e.confirm(p, now)
				p.active = false
				continue
			}
			if !e.due(p.frame, p.created, echoAck, senderAck, now) {
				e.notePending(p.created, now)
				continue
			}
			if p.unknown {
				p.active = false
				continue
			}
			if sameContent(actual, p.replacement) {
				e.confirm(p, now)
				p.active = false
				continue
			}
			e.mismatch(p.epoch)
			e.touch()
			return
		}
	}

	for i := range e.cursors {
		c := &e.cursors[i]
		if !c.active {
			continue
		}
		ax, ay, _ := base.Cursor()
		if senderAck >= c.frame && c.frame > 0 && c.x == ax && c.y == ay {
			e.confirmEpoch(c.epoch)
			c.active = false
			continue
		}
		if !e.due(c.frame, c.created, echoAck, senderAck, now) {
			e.notePending(c.created, now)
			continue
		}
		if c.x != ax || c.y != ay {
			e.mismatch(c.epoch)
			e.touch()
			return
		}
		e.confirmEpoch(c.epoch)
		c.active = false
	}

	e.tune(interval)
	e.touch()
}

func (e *Engine) due(frame uint64, created time.Time, echoAck, senderAck uint64, now time.Time) bool {
	if frame == 0 {
		return true
	}
	if echoAck >= frame {
		return true
	}
	// Test servers and older peers may not emit EchoAck.  Wait out a generous
	// echo window before treating transport acknowledgment as echo delivery.
	grace := 100 * time.Millisecond
	if e.sendInterval > grace {
		grace = e.sendInterval
	}
	return senderAck >= frame && now.Sub(created) >= grace
}

func (e *Engine) confirm(p *cellPrediction, now time.Time) {
	if !isBlank(p.replacement) && !e.matchesOriginal(p) {
		e.confirmEpoch(p.epoch)
	}
	e.repairGlitch(p.created, now)
}

func (e *Engine) matchesOriginal(p *cellPrediction) bool {
	for i := range p.originals {
		if sameContent(p.originals[i], p.replacement) {
			return true
		}
	}
	return false
}

func (e *Engine) confirmEpoch(epoch uint64) {
	if epoch > e.confirmed {
		e.confirmed = epoch
	}
}

func (e *Engine) mismatch(epoch uint64) {
	if e.mode == ModeExperimental {
		// Experimental mode keeps other predictions alive, but the failed
		// epoch is no longer trustworthy.
		e.killEpoch(epoch)
		return
	}
	if epoch > e.confirmed {
		e.killEpoch(epoch)
		return
	}
	e.reset()
}

func (e *Engine) killEpoch(epoch uint64) {
	for _, row := range e.rows {
		for i := range row.cells {
			if row.cells[i].active && row.cells[i].epoch >= epoch {
				row.cells[i].active = false
			}
		}
	}
	for i := range e.cursors {
		if e.cursors[i].active && e.cursors[i].epoch >= epoch {
			e.cursors[i].active = false
		}
	}
	if e.epoch <= epoch {
		e.epoch = epoch + 1
	}
	if !e.Pending() {
		e.haveCursor = false
	}
}

func (e *Engine) notePending(created, now time.Time) {
	age := now.Sub(created)
	switch {
	case age >= underlineAfter:
		if e.glitch < 20 {
			e.glitch = 20
			e.touch()
		}
	case age >= glitchAfter:
		if e.glitch < 10 {
			e.glitch = 10
			e.touch()
		}
	}
}

func (e *Engine) repairGlitch(created, now time.Time) {
	if now.Sub(created) >= glitchAfter || e.glitch == 0 {
		return
	}
	if now.Sub(e.lastQuick) < repairGap {
		return
	}
	e.lastQuick = now
	e.glitch--
}

func (e *Engine) tune(interval time.Duration) {
	oldShow, oldFlag := e.showOnRTT, e.flagging
	if interval > triggerHigh {
		e.showOnRTT = true
	} else if e.showOnRTT && interval <= triggerLow && !e.Pending() {
		e.showOnRTT = false
	}
	if interval > flagHigh {
		e.flagging = true
	} else if interval <= flagLow {
		e.flagging = false
	}
	if e.glitch >= 10 {
		e.flagging = true
	}
	e.sendInterval = interval
	if oldShow != e.showOnRTT || oldFlag != e.flagging {
		e.touch()
	}
}

// Render returns a deep copy of base with the currently displayable
// predictions applied.  base itself is never modified.
func (e *Engine) Render(base *vt.Terminal) *vt.Terminal {
	if base == nil {
		return nil
	}
	out := base.Clone()
	e.dirty = false
	if e.mode == ModeNever {
		return out
	}

	for y, row := range e.rows {
		for x := range row.cells {
			p := &row.cells[x]
			if !p.active || !e.visible(p.epoch) {
				continue
			}
			actual := out.Screen().At(x, y)
			if p.unknown {
				if e.flagging && !isBlank(actual) {
					actual.Attr |= vt.AttrUnderline
					out.Screen().Set(x, y, actual)
				}
				continue
			}
			c := p.replacement.Clone()
			if sameContent(c, actual) {
				continue
			}
			if e.flagging && !isBlank(c) {
				c.Attr |= vt.AttrUnderline
			}
			out.Screen().Set(x, y, c)
		}
	}

	for i := len(e.cursors) - 1; i >= 0; i-- {
		c := &e.cursors[i]
		if c.active && e.visible(c.epoch) {
			out.SetCursor(c.x, c.y)
			break
		}
	}
	return out
}

func (e *Engine) visible(epoch uint64) bool {
	switch e.mode {
	case ModeAlways, ModeExperimental:
		return true
	case ModeNever:
		return false
	}
	return e.showOnRTT || e.glitch > 0 || epoch <= e.confirmed
}

func (e *Engine) touch() {
	e.version++
	e.dirty = true
}

func sameContent(a, b vt.Cell) bool {
	if a.Raw != b.Raw || a.Wide != b.Wide || len(a.Comb) != len(b.Comb) {
		return false
	}
	for i := range a.Comb {
		if a.Comb[i] != b.Comb[i] {
			return false
		}
	}
	return true
}

func isBlank(c vt.Cell) bool {
	return (c.Raw == 0 || c.Raw == ' ') && len(c.Comb) == 0
}
