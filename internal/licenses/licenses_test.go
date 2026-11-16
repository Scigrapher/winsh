package licenses

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func component(t *testing.T, name string) Component {
	t.Helper()
	for _, c := range Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no component named %q in the inventory", name)
	return Component{}
}

// TestWinshIsGPLv3 pins the project's own licence, which is what the LICENSE
// file, --version and --show-licenses all have to agree on.
func TestWinshIsGPLv3(t *testing.T) {
	w := component(t, "winsh")
	if !strings.Contains(w.License, "GPL") {
		t.Errorf("winsh licence = %q, want a GPL-3.0 licence", w.License)
	}
	if !w.Copyleft {
		t.Errorf("winsh must be flagged copyleft")
	}
	if !strings.Contains(w.Text, "GNU GENERAL PUBLIC LICENSE") {
		t.Errorf("the winsh entry does not carry the GPL text it is licensed under")
	}
	if !strings.Contains(w.Text, "Free Software Foundation") {
		t.Errorf("the winsh entry carries a truncated GPL text")
	}
}

// TestEmbeddedLicenseMatchesLICENSE keeps the copy compiled into winsh.exe,
// which --show-licenses prints, from drifting away from the LICENSE file that
// ships with the source.  The GPL may only be copied verbatim, so a drifted
// copy is not a licence at all.
func TestEmbeddedLicenseMatchesLICENSE(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "LICENSE"))
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	shipped := strings.ReplaceAll(string(data), "\r\n", "\n")
	if shipped != GPLv3 {
		t.Errorf("internal/licenses/gpl-3.0.txt differs from LICENSE: %d bytes vs %d bytes",
			len(GPLv3), len(shipped))
	}
}

// TestReportCoversEverythingInTheBinary checks the report answers the question
// it exists to answer: what licences apply to winsh.exe.
func TestReportCoversEverythingInTheBinary(t *testing.T) {
	r := Report()
	for _, want := range []string{
		"GNU GENERAL PUBLIC LICENSE", // winsh's own terms
		"BSD-3-Clause",               // the Go standard library
		"Go Authors",                 // ... and its actual notice
		"mosh protocol",              // the protocol entry survives trimming
		"Copyleft:",                  // copyleft entries are flagged
	} {
		if !strings.Contains(r, want) {
			t.Errorf("report is missing %q", want)
		}
	}
	for _, c := range Components {
		if c.Redistributed && c.Text == "" {
			t.Errorf("%s is compiled into the binary but carries no licence text", c.Name)
		}
	}
}
