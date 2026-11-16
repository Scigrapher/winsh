package cli

import (
	"strings"
	"testing"
	"time"
)

func TestParseBasicMoshInvocation(t *testing.T) {
	c, err := Parse([]string{"user@example.com", "ls", "-la"}, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Mode != ModeInteractive {
		t.Fatalf("mode = %v", c.Mode)
	}
	if c.User != "user" || c.Host != "example.com" {
		t.Fatalf("user/host = %q/%q", c.User, c.Host)
	}
	if strings.Join(c.Command, " ") != "ls -la" {
		t.Fatalf("command = %v", c.Command)
	}
	if c.Predict != "adaptive" || !c.SSHPTY || !c.TermInit {
		t.Fatalf("defaults wrong: %+v", c)
	}
}

func TestParseMoshOptions(t *testing.T) {
	c, err := Parse([]string{
		"-a", "-o", "-4", "-p", "62000:62010",
		"--ssh=ssh -p 2222 -i /tmp/k",
		"--no-ssh-pty", "--no-init",
		"--bind-server=any", "--experimental-remote-ip=remote",
		"--server=~/src/mosh/mosh-server",
		"--", "host", "echo", "--", "dashed",
	}, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Predict != "always" || !c.PredictOver || c.Family != "inet" {
		t.Fatalf("flags: %+v", c)
	}
	if c.PortRequest != "62000:62010" {
		t.Fatalf("port = %q", c.PortRequest)
	}
	if strings.Join(c.SSHCommand, " ") != "ssh -p 2222 -i /tmp/k" {
		t.Fatalf("ssh command = %v", c.SSHCommand)
	}
	if c.SSHPTY || c.TermInit {
		t.Fatalf("--no-ssh-pty/--no-init not honoured")
	}
	if c.BindServer != "any" || c.RemoteIPMode != "remote" {
		t.Fatalf("bind/remote = %q/%q", c.BindServer, c.RemoteIPMode)
	}
	if c.Server != "~/src/mosh/mosh-server" {
		t.Fatalf("server = %q", c.Server)
	}
	if c.Host != "host" || strings.Join(c.Command, "|") != "echo|--|dashed" {
		t.Fatalf("host=%q command=%v", c.Host, c.Command)
	}
}

func TestParseLegacyOptions(t *testing.T) {
	c, err := Parse([]string{
		"--key", "AAAAAAAAAAAAAAAAAAAAAA",
		"--ssh-port", "2200",
		"--shutdown-after-idle", "300",
		"--timeout", "60",
		"--connect-timeout", "5",
		"-e",
		"10.0.0.5", "60001",
	}, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Mode != ModeDirect {
		t.Fatalf("direct mode not selected (mode=%v)", c.Mode)
	}
	if c.IP != "10.0.0.5" || c.PortRequest != "60001" {
		t.Fatalf("ip/port = %q/%q", c.IP, c.PortRequest)
	}
	if c.SSHPort != 2200 {
		t.Fatalf("ssh port = %d", c.SSHPort)
	}
	if c.IdleTimeout != 300*time.Second || c.ServerTimeout != 60*time.Second || c.ConnectTimeout != 5*time.Second {
		t.Fatalf("timeouts = %v/%v/%v", c.IdleTimeout, c.ServerTimeout, c.ConnectTimeout)
	}
	if !c.EchoCancel {
		t.Fatal("-e should be accepted")
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, "echo cancellation") {
			t.Fatalf("-e still reported as unimplemented: %q", w)
		}
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	bad := [][]string{
		{},                                // no host
		{"--predict", "sideways", "host"}, // unknown predict mode
		{"--family", "ipx", "host"},       // unknown family
		{"--experimental-remote-ip", "crystal", "h"}, // unknown remote-ip mode
		{"-p", "notaport", "host"},                   // bad port
		{"--nope", "host"},                           // unknown option
		{"--ssh"},                                    // missing argument
	}
	for _, argv := range bad {
		if _, err := Parse(argv, nil); err == nil {
			t.Errorf("Parse(%v) should have failed", argv)
		}
	}
}

func TestParseEnvDriven(t *testing.T) {
	env := map[string]string{"MOSH_KEY": "AAAAAAAAAAAAAAAAAAAAAA", "USER": "alice"}
	c, err := Parse([]string{"127.0.0.1", "60001"}, env)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Mode != ModeDirect || c.Key == "" {
		t.Fatalf("MOSH_KEY should select direct mode: %+v", c)
	}
	env2 := map[string]string{"MOSH_PREDICTION_DISPLAY": "never", "USERNAME": "bob"}
	c2, err := Parse([]string{"host"}, env2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c2.Predict != "never" {
		t.Fatalf("MOSH_PREDICTION_DISPLAY ignored")
	}
	if c2.User != "bob" {
		t.Fatalf("USERNAME not used as the default user, got %q", c2.User)
	}
}

func TestParseModes(t *testing.T) {
	c, err := Parse([]string{"-c"}, nil)
	if err != nil || c.Mode != ModeColorCount {
		t.Fatalf("-c should be the color-count mode: %v %v", c, err)
	}
	c, err = Parse([]string{"--show-licenses"}, nil)
	if err != nil || !c.ShowLicenses {
		t.Fatalf("--show-licenses: %v %v", c, err)
	}
	c, err = Parse([]string{"--version"}, nil)
	if err != nil || !c.ShowVersion {
		t.Fatalf("--version: %v %v", c, err)
	}
	c, err = Parse([]string{"--self-test"}, nil)
	if err != nil || !c.ShowSelfTest {
		t.Fatalf("--self-test: %v %v", c, err)
	}
	c, err = Parse([]string{"--fake-proxy", "--", "host", "22"}, nil)
	if err != nil || c.Mode != ModeFakeProxy {
		t.Fatalf("--fake-proxy: %v %v", c, err)
	}
	c, err = Parse([]string{"-#", "mosh -a host |", "127.0.0.1", "60001"}, map[string]string{"MOSH_KEY": "AAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil || c.Mode != ModeDirect {
		t.Fatalf("mosh-client style invocation should work: %v %v", c, err)
	}
}

func TestShellWords(t *testing.T) {
	got := shellWords(`ssh -o "ProxyJump=bastion" -i 'C:\My Keys\id_ed25519'`)
	want := []string{"ssh", "-o", "ProxyJump=bastion", "-i", `C:\My Keys\id_ed25519`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("shellWords = %q, want %q", got, want)
	}
}

func TestUsageCoversMoshOptions(t *testing.T) {
	u := Usage("winsh")
	for _, want := range []string{"--predict", "--ssh", "--no-init", "--local", "--bind-server",
		"--experimental-remote-ip", "--show-licenses", "--port", "--fake-proxy"} {
		if want == "--fake-proxy" {
			continue // intentionally undocumented, like mosh's
		}
		if !strings.Contains(u, want) {
			t.Errorf("usage text is missing %s", want)
		}
	}
}
