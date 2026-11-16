package vt

// Screen is the cell grid plus the operations the emulator needs from it.
// Everything is bounds-checked against the current geometry: a server that
// sends out-of-range coordinates is ignored, never allowed to corrupt memory.
type Screen struct {
	Cols, Rows int
	cells      []Cell
	// Version bumps whenever contents change, which lets the renderer skip
	// work when a frame is unchanged.
	Version uint64
}

// NewScreen returns a blank screen.
func NewScreen(cols, rows int) *Screen {
	if cols < 1 {
		cols = 1
	}
	if rows < 1 {
		rows = 1
	}
	s := &Screen{Cols: cols, Rows: rows, cells: make([]Cell, cols*rows)}
	// Pre-fill with blanks: a cell that was never written and a cell written
	// with a space must compare equal, or frame diffs would report changes
	// that a user cannot see.
	blank := BlankCell()
	for i := range s.cells {
		s.cells[i] = blank
	}
	return s
}

// Index converts a coordinate to a cell index, reporting false when outside.
func (s *Screen) Index(x, y int) (int, bool) {
	if x < 0 || x >= s.Cols || y < 0 || y >= s.Rows {
		return 0, false
	}
	return y*s.Cols + x, true
}

// At returns a copy of the cell at (x,y), or a blank cell when outside.
func (s *Screen) At(x, y int) Cell {
	i, ok := s.Index(x, y)
	if !ok {
		return BlankCell()
	}
	return s.cells[i]
}

// Set writes a cell.
func (s *Screen) Set(x, y int, c Cell) {
	i, ok := s.Index(x, y)
	if !ok {
		return
	}
	s.cells[i] = c
	s.Version++
}

// SetRaw overwrites only the character of a cell, keeping its attributes;
// used when a combining mark is attached.
func (s *Screen) SetCombining(x, y int, r rune) {
	i, ok := s.Index(x, y)
	if !ok {
		return
	}
	s.cells[i].AddCombining(r)
	s.Version++
}

// Row returns the cells of one row as a slice (shared storage; read-only).
func (s *Screen) Row(y int) []Cell {
	if y < 0 || y >= s.Rows {
		return nil
	}
	return s.cells[y*s.Cols : (y+1)*s.Cols]
}

// Clone deep-copies the screen.
func (s *Screen) Clone() *Screen {
	n := &Screen{Cols: s.Cols, Rows: s.Rows, cells: make([]Cell, len(s.cells)), Version: s.Version}
	for i, c := range s.cells {
		n.cells[i] = c.Clone()
	}
	return n
}

// Equal reports whether two screens hold identical cells.
func (s *Screen) Equal(o *Screen) bool {
	if s == nil || o == nil {
		return s == o
	}
	if s.Cols != o.Cols || s.Rows != o.Rows || len(s.cells) != len(o.cells) {
		return false
	}
	for i := range s.cells {
		if !s.cells[i].Equal(o.cells[i]) {
			return false
		}
	}
	return true
}

// Clear blanks the whole screen with the current pen.
func (s *Screen) Clear(pen Cell) {
	blank := pen
	blank.Raw = ' '
	blank.Comb = nil
	for i := range s.cells {
		s.cells[i] = blank
	}
	s.Version++
}

// EraseLine blanks cells [from,to) of row y with the pen.
func (s *Screen) EraseLine(y, from, to int, pen Cell) {
	if y < 0 || y >= s.Rows {
		return
	}
	if from < 0 {
		from = 0
	}
	if to > s.Cols {
		to = s.Cols
	}
	blank := pen
	blank.Raw = ' '
	blank.Comb = nil
	for x := from; x < to; x++ {
		s.cells[y*s.Cols+x] = blank
	}
	s.Version++
}

// EraseDisplay blanks according to ED modes: 0 = cursor to end,
// 1 = start to cursor, 2/3 = whole screen.
func (s *Screen) EraseDisplay(mode int, cx, cy int, pen Cell) {
	switch mode {
	case 0:
		s.EraseLine(cy, cx, s.Cols, pen)
		for y := cy + 1; y < s.Rows; y++ {
			s.EraseLine(y, 0, s.Cols, pen)
		}
	case 1:
		for y := 0; y < cy; y++ {
			s.EraseLine(y, 0, s.Cols, pen)
		}
		s.EraseLine(cy, 0, cx+1, pen)
	case 2:
		for y := 0; y < s.Rows; y++ {
			s.EraseLine(y, 0, s.Cols, pen)
		}
	case 3:
		// ED 3 clears the scrollback, which this model does not keep.
	}
}

// ScrollUp moves lines [top,bottom] up by n, blanking the bottom with pen.
func (s *Screen) ScrollUp(top, bottom, n int, pen Cell) {
	if top < 0 {
		top = 0
	}
	if bottom >= s.Rows {
		bottom = s.Rows - 1
	}
	if n <= 0 || top >= bottom {
		return
	}
	if n > bottom-top+1 {
		n = bottom - top + 1
	}
	for y := top; y+n <= bottom; y++ {
		copy(s.Row(y), s.Row(y+n))
	}
	blank := pen
	blank.Raw = ' '
	blank.Comb = nil
	for y := bottom - n + 1; y <= bottom; y++ {
		row := s.Row(y)
		for x := range row {
			row[x] = blank
		}
	}
	s.Version++
}

// ScrollDown moves lines [top,bottom] down by n, blanking the top.
func (s *Screen) ScrollDown(top, bottom, n int, pen Cell) {
	if top < 0 {
		top = 0
	}
	if bottom >= s.Rows {
		bottom = s.Rows - 1
	}
	if n <= 0 || top >= bottom {
		return
	}
	if n > bottom-top+1 {
		n = bottom - top + 1
	}
	for y := bottom; y-n >= top; y-- {
		copy(s.Row(y), s.Row(y-n))
	}
	blank := pen
	blank.Raw = ' '
	blank.Comb = nil
	for y := top; y < top+n; y++ {
		row := s.Row(y)
		for x := range row {
			row[x] = blank
		}
	}
	s.Version++
}

// InsertLines inserts n blank lines at y (within the scroll region), pushing
// lines down.
func (s *Screen) InsertLines(y, n, top, bottom int, pen Cell) {
	if y < top || y > bottom {
		return
	}
	if n > bottom-y+1 {
		n = bottom - y + 1
	}
	for i := 0; i < n; i++ {
		s.ScrollDown(y, bottom, 1, pen)
	}
}

// DeleteLines deletes n lines at y (within the scroll region).
func (s *Screen) DeleteLines(y, n, top, bottom int, pen Cell) {
	if y < top || y > bottom {
		return
	}
	if n > bottom-y+1 {
		n = bottom - y + 1
	}
	for i := 0; i < n; i++ {
		s.ScrollUp(y, bottom, 1, pen)
	}
}

// InsertChars shifts cells right from x on row y, inserting blanks.
func (s *Screen) InsertChars(x, y, n int, pen Cell) {
	if y < 0 || y >= s.Rows || x < 0 || x >= s.Cols {
		return
	}
	if n > s.Cols-x {
		n = s.Cols - x
	}
	row := s.Row(y)
	blank := pen
	blank.Raw = ' '
	blank.Comb = nil
	copy(row[x+n:], row[x:len(row)-n])
	for i := x; i < x+n; i++ {
		row[i] = blank
	}
	s.Version++
}

// DeleteChars shifts cells left from x on row y, inserting blanks at the end.
func (s *Screen) DeleteChars(x, y, n int, pen Cell) {
	if y < 0 || y >= s.Rows || x < 0 || x >= s.Cols {
		return
	}
	if n > s.Cols-x {
		n = s.Cols - x
	}
	row := s.Row(y)
	copy(row[x:], row[x+n:])
	blank := pen
	blank.Raw = ' '
	blank.Comb = nil
	for i := s.Cols - n; i < s.Cols; i++ {
		row[i] = blank
	}
	s.Version++
}

// Resize reflows by truncating or blanking, which is what terminal emulators
// do when the host changes the window size.
func (s *Screen) Resize(cols, rows int) {
	if cols < 1 {
		cols = 1
	}
	if rows < 1 {
		rows = 1
	}
	if cols == s.Cols && rows == s.Rows {
		return
	}
	n := make([]Cell, cols*rows)
	blank := BlankCell()
	for y := 0; y < rows; y++ {
		for x := 0; x < cols; x++ {
			cell := blank
			if y < s.Rows && x < s.Cols {
				cell = s.cells[y*s.Cols+x].Clone()
			}
			n[y*cols+x] = cell
		}
	}
	s.Cols, s.Rows, s.cells = cols, rows, n
	s.Version++
}

// String renders a row as plain text, trimming trailing spaces.  It is used by
// tests and by the --dump-screen diagnostic.
func (s *Screen) RowString(y int) string {
	row := s.Row(y)
	runes := make([]rune, 0, len(row))
	for _, c := range row {
		if c.Wide == WideCont {
			continue
		}
		r := c.Raw
		if r == 0 {
			r = ' '
		}
		runes = append(runes, r)
	}
	out := string(runes)
	for len(out) > 0 && out[len(out)-1] == ' ' {
		out = out[:len(out)-1]
	}
	return out
}
