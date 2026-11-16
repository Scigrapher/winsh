// Package vt is a VT220/xterm-compatible terminal emulator used for two jobs:
// it reproduces the server's screen so winsh can redraw after a disconnect,
// and it lets the client know what the user is looking at (which mosh's input
// prediction and echo-ack logic depend on).
//
// The emulator is written from the published control-sequence semantics of
// DEC VTxxx and xterm.  It deliberately keeps no per-session global state and
// performs no I/O: every operation is bounded by the current screen size, so a
// hostile or buggy server cannot make it allocate without limit.
package vt

// ColorKind describes how a cell's colour is specified.
type ColorKind uint8

// Colour kinds.
const (
	ColorDefault ColorKind = iota // terminal default
	ColorPalette                  // 0..255 palette index
	ColorRGB                      // 24-bit
)

// Color is a cell foreground or background colour.
type Color struct {
	Kind    ColorKind
	Palette uint8
	R, G, B uint8
	// Intense records the "bright" half of the 16-colour palette so that a
	// bold attribute does not have to mutate the palette index.
	Intense bool
}

// Attr holds the SGR attributes that affect presentation.
type Attr uint16

// SGR attribute bits.
const (
	AttrBold Attr = 1 << iota
	AttrDim
	AttrItalic
	AttrUnderline
	AttrBlink
	AttrReverse
	AttrHidden
	AttrStrike
	AttrDoubleUnderline
	AttrOverline
)

// Wide describes a cell's role in a double-width (East Asian) glyph.
const (
	WideNormal = uint8(iota)
	WideFirst
	WideCont
)

// Cell is one screen position.
type Cell struct {
	// Raw is the primary rune; 0 means blank.
	Raw    rune
	FG, BG Color
	Attr   Attr
	Wide   uint8
	// Comb holds combining marks following Raw.  It is nil for the common
	// case; the allocation is only paid for when a combining mark arrives.
	Comb []rune
}

// BlankCell returns the cell used for erased positions.
func BlankCell() Cell {
	return Cell{Raw: ' ', FG: Color{Kind: ColorDefault}, BG: Color{Kind: ColorDefault}}
}

// IsBlank reports whether the cell renders as an unstyled space.
func (c Cell) IsBlank() bool {
	return (c.Raw == ' ' || c.Raw == 0) && c.Attr == 0 &&
		c.FG.Kind == ColorDefault && c.BG.Kind == ColorDefault && len(c.Comb) == 0
}

// Equal compares two cells including their attributes.
func (c Cell) Equal(o Cell) bool {
	if c.Raw != o.Raw || c.Attr != o.Attr || c.Wide != o.Wide || len(c.Comb) != len(o.Comb) {
		return false
	}
	if c.FG != o.FG || c.BG != o.BG {
		return false
	}
	for i := range c.Comb {
		if c.Comb[i] != o.Comb[i] {
			return false
		}
	}
	return true
}

// Clone returns an independent copy of the cell (combining marks included).
func (c Cell) Clone() Cell {
	if len(c.Comb) > 0 {
		n := c
		n.Comb = append([]rune(nil), c.Comb...)
		return n
	}
	return c
}

// maxCombining bounds how many combining marks attach to one base glyph.
// Beyond that they are dropped, which keeps a pathological server from
// growing memory without bound.
const maxCombining = 8

// AddCombining attaches a combining mark to the cell.
func (c *Cell) AddCombining(r rune) {
	if len(c.Comb) >= maxCombining {
		return
	}
	c.Comb = append(c.Comb, r)
}
