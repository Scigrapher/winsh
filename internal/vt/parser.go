package vt

// The escape-sequence parser: a byte-driven state machine covering the C0
// controls, ESC/CSI/DCS/OSC/APC forms, and UTF-8 decoding.  Anything not
// recognised is consumed and counted, never allowed to stall the stream: a
// terminal that wedges on an unknown sequence is a denial-of-service against
// its own user.

// parse states.
const (
	stGround = iota
	stEsc
	stEscIntermediate
	stEscPriv
	stCSI
	stCSIIntermediate
	stCSIPrivCollect
	stOSC
	stDCS
	stAPC
	stIgnore
)

const (
	maxCSIGroups        = 64
	maxCSISubparams     = 32
	maxCSIIntermediates = 8
)

type parseState struct {
	state   int
	groups  [][]int
	cur     []int
	inParam bool
	// colon[k] records whether group k was written with ":" separators, i.e.
	// is a sub-parameter list.  SGR needs it to tell the colon form of an
	// extended colour (38:2::r:g:b) from a semicolon form whose first
	// component is genuinely zero (38;2;0;r;g;b).
	colon    []bool
	curColon bool
	private  byte
	interm   []byte
	osc      []byte
	utf8     rune
	utf8Need int
	utf8Seen int
	// afterCharset is set once ESC ( or ESC ) has been seen and the chosen
	// charset byte is still to come.
	afterCharset bool
	charsetSlot  byte
	overflow     bool
}

// Feed consumes terminal output from the host.
func (t *Terminal) Feed(data []byte) {
	for _, b := range data {
		t.feedByte(b)
	}
}

func (t *Terminal) feedByte(b byte) {
	p := &t.ps
	if p.overflow {
		t.overflowByte(b)
		return
	}
	switch p.state {
	case stGround:
		t.ground(b)
	case stEsc:
		t.escState(b)
	case stEscIntermediate, stEscPriv:
		t.escSlowState(b)
	case stCSI, stCSIPrivCollect:
		t.csiState(b)
	case stCSIIntermediate:
		if b >= 0x20 && b <= 0x2F {
			t.appendIntermediate(b)
			return
		}
		if b >= 0x40 && b <= 0x7E {
			t.dispatchCSI(b)
			p.state = stGround
			return
		}
		p.state = stGround
	case stOSC, stDCS, stAPC:
		t.stringState(b)
	case stIgnore:
		// Consuming until a string terminator or a CSI final byte.
		if b == 0x1B {
			p.state = stEsc
			t.beginEsc()
			return
		}
	default:
		p.state = stGround
	}
}

// overflowByte consumes the remainder of an over-long control sequence
// without allocating more parameter storage, then returns to ground at the
// sequence final.
func (t *Terminal) overflowByte(b byte) {
	p := &t.ps
	switch {
	case b == 0x1B:
		t.beginEsc()
	case b == 0x18 || b == 0x1A:
		p.state = stGround
		p.overflow = false
	case b >= 0x40 && b <= 0x7E:
		p.state = stGround
		p.overflow = false
	}
}

func (t *Terminal) markOverflow() {
	t.ps.overflow = true
	t.ps.groups = t.ps.groups[:0]
	t.ps.colon = t.ps.colon[:0]
	t.ps.cur = t.ps.cur[:0]
	t.ps.interm = t.ps.interm[:0]
}

func (t *Terminal) appendIntermediate(b byte) {
	if len(t.ps.interm) >= maxCSIIntermediates {
		t.markOverflow()
		return
	}
	t.ps.interm = append(t.ps.interm, b)
}

func (t *Terminal) ground(b byte) {
	p := &t.ps
	if b == 0x1B {
		// An escape sequence interrupts a partial UTF-8 character, which is
		// reported as invalid.  Flushing here (rather than only on the next
		// printable byte) is what makes a rendered frame diff reproduce the
		// sender's screen exactly.
		t.flushPartialUTF8()
		p.state = stEsc
		t.beginEsc()
		return
	}
	if b < 0x20 {
		t.flushPartialUTF8()
		t.executeC0(b)
		return
	}
	if b < 0x80 {
		// Fast path for ASCII.
		t.flushPartialUTF8()
		t.PutRune(rune(b))
		return
	}
	// UTF-8.
	if p.utf8Seen < p.utf8Need || (p.utf8Seen == 0 && p.utf8Need == 0 && false) {
		// unreachable guard kept for clarity
	}
	if p.utf8Seen > 0 && p.utf8Seen < p.utf8Need {
		if b >= 0x80 && b < 0xC0 {
			p.utf8 = p.utf8<<6 | rune(b&0x3F)
			p.utf8Seen++
			if p.utf8Seen == p.utf8Need {
				r := p.utf8
				p.utf8Seen = 0
				p.utf8Need = 0
				if !validRune(r) {
					r = 0xFFFD
				}
				t.PutRune(r)
			}
			return
		}
		// Invalid continuation: restart and re-process this byte.
		p.utf8Seen = 0
		p.utf8Need = 0
		t.PutRune(0xFFFD)
		t.ground(b)
		return
	}
	switch {
	case b >= 0xC2 && b <= 0xDF:
		p.utf8 = rune(b & 0x1F)
		p.utf8Need = 2
	case b >= 0xE0 && b <= 0xEF:
		p.utf8 = rune(b & 0x0F)
		p.utf8Need = 3
	case b >= 0xF0 && b <= 0xF4:
		p.utf8 = rune(b & 0x07)
		p.utf8Need = 4
	default:
		// Overlong, surrogate, or out-of-range lead byte.
		p.utf8Seen = 0
		p.utf8Need = 0
		t.PutRune(0xFFFD)
		if b >= 0x80 {
			return
		}
		t.ground(b)
		return
	}
	p.utf8Seen = 1
}

// flushPartialUTF8 reports an interrupted multi-byte character.
func (t *Terminal) flushPartialUTF8() {
	if t.ps.utf8Seen > 0 {
		t.ps.utf8Seen = 0
		t.ps.utf8Need = 0
		t.PutRune(0xFFFD)
	}
}

func validRune(r rune) bool {
	return r >= 0 && r <= 0x10FFFF && !(r >= 0xD800 && r <= 0xDFFF)
}

func (t *Terminal) executeC0(b byte) {
	switch b {
	case 0x07: // BEL - ignored (no audible output from a replica)
	case 0x08: // BS
		t.Backspace()
	case 0x09: // HT
		t.Tab()
	case 0x0A, 0x0B, 0x0C: // LF, VT, FF
		t.lineFeed()
		t.version++
	case 0x0D: // CR
		t.CarriageReturn()
	case 0x0E: // SO: shift out selects GR; we only emulate GL mapping
		t.ps.state = stGround
	case 0x0F: // SI
		t.ps.state = stGround
	case 0x18, 0x1A: // CAN, SUB abort any sequence in progress
		t.ps.state = stGround
		t.ps.utf8Seen = 0
		t.ps.utf8Need = 0
	default:
		// NUL and the remaining C0 controls are ignored.
	}
}

func (t *Terminal) beginEsc() {
	p := &t.ps
	p.state = stEsc
	p.groups = p.groups[:0]
	p.colon = p.colon[:0]
	p.cur = p.cur[:0]
	p.inParam = false
	p.curColon = false
	p.private = 0
	p.interm = p.interm[:0]
	p.osc = p.osc[:0]
	p.afterCharset = false
	p.charsetSlot = 0
	p.overflow = false
}

func (t *Terminal) escState(b byte) {
	p := &t.ps
	switch b {
	case '[':
		p.state = stCSI
		return
	case 'P': // DCS
		p.state = stDCS
		return
	case ']': // OSC
		p.state = stOSC
		return
	case '_', '^', 'X': // APC, PM, SOS
		p.state = stAPC
		return
	case '(', ')', '*', '+':
		p.afterCharset = true
		p.charsetSlot = b
		p.state = stEscIntermediate
		return
	case '7':
		t.savedX, t.savedY, t.savedPen = t.x, t.y, t.pen
		p.state = stGround
	case '8':
		t.moveTo(t.clampX(t.savedX), t.clampY(t.savedY))
		t.pen = t.savedPen
		p.state = stGround
	case 'M': // RI
		t.reverseLineFeed()
		p.state = stGround
	case 'D': // IND
		t.lineFeed()
		p.state = stGround
	case 'E': // NEL
		t.CarriageReturn()
		t.lineFeed()
		p.state = stGround
	case 'c': // RIS
		t.Reset()
	case '=': // DECKPAM
		t.appKeypad = true
		p.state = stGround
	case '>': // DECKPNM
		t.appKeypad = false
		p.state = stGround
	case 'n', 'o': // SS2/SS3 single-shift: unsupported, ignore
		p.state = stGround
	default:
		if b >= 0x20 && b <= 0x2F {
			t.appendIntermediate(b)
			p.state = stEscIntermediate
			return
		}
		if b == 0x1B {
			t.beginEsc()
			return
		}
		t.UnknownSeqs++
		p.state = stGround
	}
}

func (t *Terminal) escSlowState(b byte) {
	p := &t.ps
	if p.afterCharset {
		switch {
		case b == '0':
			if p.charsetSlot == '(' {
				t.decDrawing = true
				t.charsetGL = '0'
			}
		case b == 'B' || b == 'A':
			if p.charsetSlot == '(' {
				t.decDrawing = false
				t.charsetGL = b
			}
		default:
			t.UnknownSeqs++
		}
		p.afterCharset = false
		p.state = stGround
		return
	}
	if b >= 0x20 && b <= 0x2F {
		t.appendIntermediate(b)
		return
	}
	if b >= 0x30 && b <= 0x7E {
		// Intermediate-qualified ESC final: unsupported (DECALN etc.).
		t.UnknownSeqs++
		p.state = stGround
		return
	}
	p.state = stGround
}

func (t *Terminal) csiState(b byte) {
	p := &t.ps
	switch {
	case b >= '0' && b <= '9':
		p.inParam = true
		if len(p.groups) == 0 && len(p.cur) == 0 {
			p.cur = append(p.cur, int(b-'0'))
		} else if len(p.cur) == 0 {
			p.cur = append(p.cur, int(b-'0'))
		} else {
			i := len(p.cur) - 1
			if p.cur[i] > 100000 {
				p.cur[i] = 100000 // clamp absurd parameters
			} else {
				p.cur[i] = p.cur[i]*10 + int(b-'0')
			}
		}
		return
	case b == ';':
		if len(p.groups) >= maxCSIGroups {
			t.markOverflow()
			return
		}
		// Copy: p.cur is reused for the next group, so appending it directly
		// would let a later digit overwrite an earlier parameter.
		t.pushGroup()
		p.inParam = false
		return
	case b == ':':
		// Sub-parameter separator (SGR truecolor colon form).
		if len(p.cur) >= maxCSISubparams {
			t.markOverflow()
			return
		}
		p.cur = append(p.cur, 0)
		p.curColon = true
		return
	case b == '?' || b == '>' || b == '=' || b == '!':
		p.private = b
		return
	case b >= 0x20 && b <= 0x2F:
		t.appendIntermediate(b)
		return
	case b >= 0x40 && b <= 0x7E:
		if p.inParam || len(p.cur) > 0 || len(p.groups) > 0 {
			t.pushGroup()
		}
		t.dispatchCSI(b)
		p.state = stGround
		return
	default:
		p.state = stGround
	}
}

// pushGroup closes the parameter being accumulated and opens the next one,
// recording whether the group used ":" separators.
func (t *Terminal) pushGroup() {
	p := &t.ps
	if len(p.groups) >= maxCSIGroups {
		t.markOverflow()
		return
	}
	p.groups = append(p.groups, append([]int(nil), p.cur...))
	p.colon = append(p.colon, p.curColon)
	p.cur = p.cur[:0]
	p.curColon = false
}

// param returns the i-th parameter, 1-based, or def when absent.
func (t *Terminal) param(i, def int) int {
	if i-1 < 0 || i-1 >= len(t.ps.groups) {
		return def
	}
	g := t.ps.groups[i-1]
	if len(g) == 0 {
		return def
	}
	return g[0]
}

// subparams returns the sub-parameter list of the i-th (1-based) group.
func (t *Terminal) subparams(i int) []int {
	if i-1 < 0 || i-1 >= len(t.ps.groups) {
		return nil
	}
	return t.ps.groups[i-1]
}

func (t *Terminal) nparams() int { return len(t.ps.groups) }

func (t *Terminal) stringState(b byte) {
	p := &t.ps
	if b == 0x07 { // BEL terminates
		t.finishString()
		p.state = stGround
		return
	}
	if b == 0x1B {
		// Hope for ST (ESC \); swallow and let escState decide.
		t.finishString()
		p.state = stEsc
		t.beginEsc()
		return
	}
	if b == 0x9C {
		t.finishString()
		p.state = stGround
		return
	}
	if len(p.osc) < 4096 {
		p.osc = append(p.osc, b)
	}
}

func (t *Terminal) finishString() {
	p := &t.ps
	if p.state == stOSC {
		t.handleOSC(p.osc)
	}
	p.osc = p.osc[:0]
}

// handleOSC implements the operating-system commands that are safe and
// meaningful for a display replica.
//
// Deliberately NOT implemented: OSC 52 (clipboard copy/paste), which is a
// well-known channel for exfiltrating data from a remote shell session, and
// OSC 7 (cwd reporting).  Both are consumed and discarded.
func (t *Terminal) handleOSC(s []byte) {
	str := string(s)
	for {
		if len(str) > 0 && str[0] == 0x1B {
			str = str[1:]
			if len(str) > 0 && str[0] == '\\' {
				break
			}
		}
		break
	}
	semi := -1
	for i := 0; i < len(str); i++ {
		if str[i] == ';' {
			semi = i
			break
		}
	}
	if semi < 0 {
		return
	}
	numStr := str[:semi]
	payload := str[semi+1:]
	num := 0
	bad := len(numStr) == 0
	for i := 0; i < len(numStr); i++ {
		if numStr[i] < '0' || numStr[i] > '9' {
			bad = true
			break
		}
		num = num*10 + int(numStr[i]-'0')
	}
	if bad {
		return
	}
	switch num {
	case 0, 2: // icon and window title
		t.title = payload
		t.haveTitle = true
		t.version++
	case 1: // icon name: ignored, we have no icon
	case 4, 10, 11, 12, 104, 110, 111, 112, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1010, 1011, 1012, 1013, 1014, 1015, 1016:
		// Palette and colour queries/sets: presentation hints only.  The
		// local terminal's palette is authoritative, so these are dropped.
	default:
		t.UnknownSeqs++
	}
}
