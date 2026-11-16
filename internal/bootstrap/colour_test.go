package bootstrap

import "testing"

// ColourCount decides how many colours mosh-server advertises to everything on
// the far side, so getting it wrong silently caps the session at 256 colours no
// matter that winsh can render 24-bit.
func TestColorCountAdvertisesTruecolor(t *testing.T) {
	cases := []struct {
		name string
		term string
		cct  string
		want int
	}{
		{"truecolor via COLORTERM", "xterm-256color", "truecolor", 16777216},
		{"24bit via COLORTERM", "xterm", "24bit", 16777216},
		{"truecolor in TERM", "xterm-truecolor", "", 16777216},
		{"direct in TERM", "direct-color", "", 16777216},
		{"plain 256", "xterm-256color", "", 256},
		{"88 colour", "xterm-88color", "", 88},
		{"no TERM at all", "", "", 256},
		{"mono", "tty-mono", "", 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			if tc.cct == "" {
				unsetForTest(t, "COLORTERM")
			} else {
				t.Setenv("COLORTERM", tc.cct)
			}
			if got := ColorCount(); got != tc.want {
				t.Errorf("TERM=%q COLORTERM=%q: ColorCount()=%d, want %d", tc.term, tc.cct, got, tc.want)
			}
		})
	}
}

// TestLocaleVarsForwardCOLORTERM: -c alone does not make far-side programs emit
// 38;2;r;g;b -- they look at COLORTERM.
func TestLocaleVarsForwardCOLORTERM(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("COLORTERM", "truecolor")
	found := false
	for _, kv := range localeVars() {
		if kv == "COLORTERM=truecolor" {
			found = true
		}
	}
	if !found {
		t.Errorf("COLORTERM not forwarded to mosh-server: %v", localeVars())
	}

	t.Setenv("TERM", "xterm-truecolor")
	unsetForTest(t, "COLORTERM")
	found = false
	for _, kv := range localeVars() {
		if kv == "COLORTERM=truecolor" {
			found = true
		}
	}
	if !found {
		t.Errorf("truecolor TERM did not imply COLORTERM=truecolor: %v", localeVars())
	}
}

func unsetForTest(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	// t.Setenv cannot unset; an empty value is treated as absent by the code
	// under test, which is the behaviour we rely on.
}
