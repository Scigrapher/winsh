package vt

import (
	"strings"
	"testing"
)

func TestCSIGroupsAreBoundedAndParserRecovers(t *testing.T) {
	tr := NewTerminal(32, 2)
	tr.Feed([]byte("\x1b[" + strings.Repeat(";", maxCSIGroups*8) + "mOK"))
	if len(tr.ps.groups) > maxCSIGroups {
		t.Fatalf("stored %d CSI groups, cap is %d", len(tr.ps.groups), maxCSIGroups)
	}
	if got := tr.Screen().RowString(0); !strings.Contains(got, "OK") {
		t.Fatalf("parser did not recover after over-long CSI: %q", got)
	}
}

func TestCSISubparamsAreBounded(t *testing.T) {
	tr := NewTerminal(32, 2)
	tr.Feed([]byte("\x1b[38" + strings.Repeat(":", maxCSISubparams*8) + "mX"))
	if len(tr.ps.cur) > maxCSISubparams {
		t.Fatalf("stored %d CSI subparameters, cap is %d", len(tr.ps.cur), maxCSISubparams)
	}
	if got := tr.Screen().RowString(0); !strings.Contains(got, "X") {
		t.Fatalf("parser did not recover after over-long SGR: %q", got)
	}
}

func TestCSIIntermediatesAreBounded(t *testing.T) {
	tr := NewTerminal(32, 2)
	tr.Feed([]byte("\x1b[" + strings.Repeat(" ", maxCSIIntermediates*8) + "mY"))
	if len(tr.ps.interm) > maxCSIIntermediates {
		t.Fatalf("stored %d CSI intermediates, cap is %d", len(tr.ps.interm), maxCSIIntermediates)
	}
	if got := tr.Screen().RowString(0); !strings.Contains(got, "Y") {
		t.Fatalf("parser did not recover after over-long intermediate sequence: %q", got)
	}
}
