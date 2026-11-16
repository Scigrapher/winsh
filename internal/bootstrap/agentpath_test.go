package bootstrap

import "testing"

func TestSSHAgentPathUsesForwardSlashes(t *testing.T) {
	got := sshAgentPath(`\\.\pipe\pageant.bob.abc123`)
	want := `//./pipe/pageant.bob.abc123`
	if got != want {
		t.Errorf("sshAgentPath = %q, want %q", got, want)
	}
}
