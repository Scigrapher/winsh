package vt

import "fmt"

// rowCells renders a row's cells compactly for diagnostics.
func rowCells(s *Screen, y int, upto int) string {
	if y < 0 || y >= s.Rows {
		return "out of range"
	}
	out := ""
	for x := 0; x < upto && x < s.Cols; x++ {
		c := s.At(x, y)
		out += fmt.Sprintf("[%d:%q w%d a%d] ", x, string(c.Raw), c.Wide, c.Attr)
	}
	return out
}
