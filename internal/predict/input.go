package predict

import "unicode/utf8"

// inputEvent is the small subset of user input that can be predicted safely.
// Anything else starts a new prediction epoch instead of guessing.
type inputEvent struct {
	kind eventKind
	r    rune
}

type eventKind uint8

const (
	eventRune eventKind = iota
	eventBackspace
	eventCarriageReturn
	eventLineFeed
	eventLeft
	eventRight
	eventUnsupported
)

const (
	inputGround = iota
	inputEscape
	inputCSI
	inputSS3
)

// inputParser decodes terminal input bytes into prediction events.  It keeps
// its state across calls because key events and escape sequences may arrive in
// separate reads.
type inputParser struct {
	state int
	seq   []byte
	utf   [utf8.UTFMax]byte
	utfN  int
	utfM  int
	ev    []inputEvent
}

func (p *inputParser) reset() {
	p.state = inputGround
	p.seq = p.seq[:0]
	p.utfN = 0
	p.utfM = 0
	p.ev = p.ev[:0]
}

func (p *inputParser) feed(data []byte) []inputEvent {
	p.ev = p.ev[:0]
	for _, b := range data {
		p.feedByte(b)
	}
	return p.ev
}

func (p *inputParser) feedByte(b byte) {
	switch p.state {
	case inputEscape:
		switch b {
		case '[':
			p.state = inputCSI
			p.seq = append(p.seq[:0], 0x1b, '[')
		case 'O':
			p.state = inputSS3
			p.seq = append(p.seq[:0], 0x1b, 'O')
		default:
			p.state = inputGround
			p.seq = p.seq[:0]
			p.ev = append(p.ev, inputEvent{kind: eventUnsupported})
		}
		return
	case inputCSI, inputSS3:
		if len(p.seq) < 32 {
			p.seq = append(p.seq, b)
		} else {
			p.state = inputGround
			p.seq = p.seq[:0]
			p.ev = append(p.ev, inputEvent{kind: eventUnsupported})
			return
		}
		if b < 0x40 || b > 0x7e {
			return
		}
		p.finishSequence()
		return
	}

	if p.utfN > 0 {
		if b < 0x80 || b > 0xbf {
			p.utfN, p.utfM = 0, 0
			p.ev = append(p.ev, inputEvent{kind: eventUnsupported})
			p.feedByte(b)
			return
		}
		p.utf[p.utfN] = b
		p.utfN++
		if p.utfN < p.utfM {
			return
		}
		r, size := utf8.DecodeRune(p.utf[:p.utfN])
		p.utfN, p.utfM = 0, 0
		if r == utf8.RuneError && size == 1 {
			p.ev = append(p.ev, inputEvent{kind: eventUnsupported})
			return
		}
		p.ev = append(p.ev, inputEvent{kind: eventRune, r: r})
		return
	}

	switch {
	case b == 0x1b:
		p.state = inputEscape
	case b == 0x08 || b == 0x7f:
		p.ev = append(p.ev, inputEvent{kind: eventBackspace})
	case b == 0x0d:
		p.ev = append(p.ev, inputEvent{kind: eventCarriageReturn})
	case b == 0x0a:
		p.ev = append(p.ev, inputEvent{kind: eventLineFeed})
	case b == 0x09 || b < 0x20:
		p.ev = append(p.ev, inputEvent{kind: eventUnsupported})
	case b < 0x80:
		p.ev = append(p.ev, inputEvent{kind: eventRune, r: rune(b)})
	default:
		var need int
		switch {
		case b >= 0xc2 && b <= 0xdf:
			need = 2
		case b >= 0xe0 && b <= 0xef:
			need = 3
		case b >= 0xf0 && b <= 0xf4:
			need = 4
		default:
			p.ev = append(p.ev, inputEvent{kind: eventUnsupported})
			return
		}
		p.utf[0] = b
		p.utfN, p.utfM = 1, need
	}
}

func (p *inputParser) finishSequence() {
	seq := p.seq
	p.state = inputGround
	p.seq = p.seq[:0]

	// Application-cursor mode uses SS3; normal xterm mode uses CSI.  Only the
	// plain, unmodified left and right arrows are predictable.
	if len(seq) == 3 && seq[0] == 0x1b &&
		(seq[1] == '[' || seq[1] == 'O') {
		switch seq[2] {
		case 'C':
			p.ev = append(p.ev, inputEvent{kind: eventRight})
			return
		case 'D':
			p.ev = append(p.ev, inputEvent{kind: eventLeft})
			return
		}
	}
	p.ev = append(p.ev, inputEvent{kind: eventUnsupported})
}
