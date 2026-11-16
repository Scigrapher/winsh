package bootstrap

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"winsh/internal/cli"
)

func TestServerArgumentsKeepUntrustedValuesLiteral(t *testing.T) {
	c := &cli.Config{
		Host:        "host & calc",
		PortRequest: "60000:61000",
		Command:     []string{"echo", "a & b", "> redirected"},
	}
	args := serverArguments(c, Options{Colors: 8}, c.Host)
	joined := strings.Join(args, "\x00")
	for _, want := range []string{c.Host, c.PortRequest, "a & b", "> redirected"} {
		if !strings.Contains(joined, want) {
			t.Errorf("arguments %q do not contain literal %q", args, want)
		}
	}

	line := serverCommandLine(c, Options{Colors: 8}, c.Host)
	for _, want := range []string{"'host & calc'", "'a & b'", "'> redirected'"} {
		if !strings.Contains(line, want) {
			t.Errorf("remote command %q does not quote %q", line, want)
		}
	}
}

func TestBootstrapLineBufferHasHardLimit(t *testing.T) {
	r := &chunkReader{buf: make([]byte, maxBootstrapLine)}
	if err := r.append([]byte{0}); err == nil {
		t.Fatal("bootstrap reader accepted an output line beyond its hard limit")
	}
}

func TestLocalServerCommandDoesNotUseAShell(t *testing.T) {
	c := &cli.Config{Server: "mosh-server-test", Host: "host & calc"}
	cmd := localServerCommand(c, Options{Colors: 8})
	if len(cmd.Args) == 0 || cmd.Args[0] != c.Server {
		t.Fatalf("local command argv = %q", cmd.Args)
	}
	if base := strings.ToLower(filepath.Base(cmd.Args[0])); base == "cmd.exe" || base == "powershell.exe" {
		t.Fatalf("local command was routed through a shell: %q", cmd.Args)
	}
	for _, arg := range cmd.Args[1:] {
		if arg == "/c" || arg == "-Command" {
			t.Fatalf("local command contains shell invocation argument %q", arg)
		}
	}
}

func TestRemoteBannerCannotSpoofWithoutPrefixOrControls(t *testing.T) {
	var out bytes.Buffer
	printRemoteBanner(&out, "first\nwinsh: fake prompt \x1b]52;c;secret\x07")
	got := out.String()
	if strings.Count(got, "winsh: remote banner:") != 2 {
		t.Fatalf("banner output lacks a prefix on every line: %q", got)
	}
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Fatalf("banner output contains terminal controls: %q", got)
	}
}
