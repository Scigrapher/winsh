// Package cli parses winsh's command line.
//
// The surface is mosh's: the long and short options that mosh 1.4 accepts work
// here with the same meaning, and the options that older mosh releases
// accepted (such as --key and --shutdown-after-idle) are accepted too.
// Everything winsh adds is clearly marked as such in --help.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Version is winsh's version string.
const Version = "1.0.0"

// Program is the name used in messages.
const Program = "winsh"

// Modes select one of the entry points the binary provides.
type Mode int

// Entry-point modes.
const (
	// ModeInteractive is the normal "mosh user@host" path.
	ModeInteractive Mode = iota
	// ModeFakeProxy implements mosh's --fake-proxy ProxyCommand helper.
	ModeFakeProxy
	// ModeColorCount answers "how many colors does TERM support" (-c), which
	// the mosh wrapper protocol expects.
	ModeColorCount
	// ModeDirect connects straight to a server with a known port and key,
	// standing in for mosh-client (MOSH_KEY plus "IP PORT" arguments).
	ModeDirect
	// ModeInfo answers --version, --help, --show-licenses, --diagnostics.
	ModeInfo
)

// Config is the parsed command line.
type Config struct {
	Mode Mode

	Host    string
	User    string
	Command []string
	// IP is set when the caller already knows the numeric address.
	IP string

	Client       string
	Server       string
	Predict      string
	PredictOver  bool
	Family       string
	PortRequest  string
	SSHCommand   []string
	SSHPTY       bool
	TermInit     bool
	Local        bool
	BindServer   string
	RemoteIPMode string
	ProxyCommand string
	SSHOptions   []string

	// Legacy mosh options that still make sense.
	Key             string
	SSHPort         int
	UDPPort         string
	AvoidUDPPort    string
	IdleTimeout     time.Duration
	ServerTimeout   time.Duration
	ConnectTimeout  time.Duration
	EchoCancel      bool
	MoshClientStyle bool

	// TitleNoPrefix suppresses the "[winsh] " window-title prefix, matching
	// MOSH_TITLE_NOPREFIX.
	TitleNoPrefix bool
	// EscapeKey is the byte that starts the control sequence; -1 disables it.
	EscapeKey int

	Verbose      bool
	Diag         bool
	DumpScreen   bool
	ShowLicenses bool
	ShowSelfTest bool
	// ShowKeys answers --list-keys, a winsh-specific report of the keys an
	// agent (Pageant first) and ~/.ssh make available.
	ShowKeys bool
	// NoEscapeKey disables the control-key sequence entirely.
	NoEscapeKey bool
	ShowVersion bool
	ShowHelp    bool

	// NativeSSH forces winsh's own SSH client; ExternalSSH forces an external
	// ssh(1).  When both are false, winsh prefers its own client so that
	// Pageant and ~/.ssh keys both work without an external program.
	NativeSSH   bool
	ExternalSSH bool

	// Warnings are non-fatal notes to show the user.
	Warnings []string
}

// DefaultConfig returns the option values mosh would use.
func DefaultConfig() *Config {
	return &Config{
		Client:         "mosh-client",
		Server:         "mosh-server",
		Predict:        "adaptive",
		Family:         "prefer-inet",
		SSHPTY:         true,
		TermInit:       true,
		BindServer:     "ssh",
		RemoteIPMode:   "proxy",
		ConnectTimeout: 15 * time.Second,
	}
}

// ErrUsage asks the caller to print usage and exit non-zero.
var ErrUsage = errors.New(Program + ": usage error")

// Parse builds a Config from argv (without the program name) and the
// environment.
func Parse(argv []string, env map[string]string) (*Config, error) {
	c := DefaultConfig()
	if v, ok := lookup(env, "MOSH_PREDICTION_DISPLAY"); ok && v != "" {
		c.Predict = v
	}
	if v, ok := lookup(env, "MOSH_TITLE_NOPREFIX"); ok && v != "" {
		c.TitleNoPrefix = true
	}
	if v, ok := lookup(env, "MOSH_ESCAPE_KEY"); ok {
		// The rules are mosh's, including its refusal to let you set the
		// escape key to something you will need in order to leave or to type a
		// newline.  An out-of-range or multi-character value is not an error:
		// mosh quietly falls back to Ctrl-^, and so does winsh, because
		// failing to start is a worse outcome than a familiar default.
		switch {
		case v == "":
			c.EscapeKey = -1
		case len(v) == 1 && v[0] > 0 && v[0] < 128:
			c.EscapeKey = int(v[0])
			switch c.EscapeKey {
			case 0x03, 0x04, 0x0A, 0x0C, 0x0D: // Ctrl-C, Ctrl-D, LF, Ctrl-L, CR
				c.EscapeKey = 0 // 0 means "use the default", which is Ctrl-^
			}
		}
	}
	if v, ok := lookup(env, "MOSH_KEY"); ok && v != "" {
		c.Key = v
		c.MoshClientStyle = true
	}

	var positional []string
	// mosh's wrapper stops option processing at the first non-option argument,
	// so "mosh host ls -la" sends "ls -la" to the server rather than trying to
	// parse -la as a winsh option.  Everything after the first positional is
	// therefore positional.
	sawPositional := false
	i := 0
	takeValue := func(name, arg string) (string, error) {
		if arg != "" {
			return arg, nil
		}
		if i+1 >= len(argv) {
			return "", fmt.Errorf("%w: %s requires an argument", ErrUsage, name)
		}
		i++
		return argv[i], nil
	}

	for ; i < len(argv); i++ {
		arg := argv[i]
		if sawPositional {
			positional = append(positional, argv[i:]...)
			break
		}
		if arg == "--" {
			positional = append(positional, argv[i+1:]...)
			break
		}
		name, inline := arg, ""
		if strings.HasPrefix(arg, "--") {
			if eq := strings.Index(arg, "="); eq >= 0 {
				name, inline = arg[:eq], arg[eq+1:]
			}
		}
		switch name {
		case "-h", "--help":
			c.ShowHelp = true
			c.Mode = ModeInfo
		case "--version":
			c.ShowVersion = true
			c.Mode = ModeInfo
		case "--show-licenses", "--licenses":
			c.ShowLicenses = true
			c.Mode = ModeInfo
		case "--diagnostics", "--diag":
			c.Diag = true
			c.Mode = ModeInfo
		case "--list-keys":
			c.ShowKeys = true
			c.Mode = ModeInfo
		case "--self-test":
			c.ShowSelfTest = true
			c.Mode = ModeInfo
		case "--no-escape-key":
			c.NoEscapeKey = true
			c.EscapeKey = -1
		case "--dump-screen":
			c.DumpScreen = true
		case "-v", "--verbose":
			c.Verbose = true
		case "-#":
			// mosh passes the original wrapper command line to mosh-client as
			// "-# <args> |"; it is informational only.
			if _, err := takeValue("-#", inline); err != nil {
				return nil, err
			}
			c.MoshClientStyle = true
		case "-c":
			c.Mode = ModeColorCount
			c.MoshClientStyle = true
		case "--predict":
			v, err := takeValue("--predict", inline)
			if err != nil {
				return nil, err
			}
			c.Predict = v
		case "-a":
			c.Predict = "always"
		case "-n":
			c.Predict = "never"
		case "-o", "--predict-overwrite":
			c.PredictOver = true
		case "--family":
			v, err := takeValue("--family", inline)
			if err != nil {
				return nil, err
			}
			c.Family = v
		case "-4":
			c.Family = "inet"
		case "-6":
			c.Family = "inet6"
		case "-p", "--port":
			v, err := takeValue(name, inline)
			if err != nil {
				return nil, err
			}
			c.PortRequest = v
		case "--udp-port":
			v, err := takeValue("--udp-port", inline)
			if err != nil {
				return nil, err
			}
			c.UDPPort = v
			c.PortRequest = v
		case "--avoid-udp-port":
			v, err := takeValue("--avoid-udp-port", inline)
			if err != nil {
				return nil, err
			}
			c.AvoidUDPPort = v
		case "--ssh":
			v, err := takeValue("--ssh", inline)
			if err != nil {
				return nil, err
			}
			c.SSHCommand = shellWords(v)
			c.ExternalSSH = true
		case "--ssh-option":
			v, err := takeValue(name, inline)
			if err != nil {
				return nil, err
			}
			c.SSHOptions = append(c.SSHOptions, v)
		case "--ssh-port":
			v, err := takeValue("--ssh-port", inline)
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > 65535 {
				return nil, fmt.Errorf("%w: --ssh-port wants a port number", ErrUsage)
			}
			c.SSHPort = n
		case "--ssh-proxy-command":
			v, err := takeValue("--ssh-proxy-command", inline)
			if err != nil {
				return nil, err
			}
			c.ProxyCommand = v
		case "--ssh-pty":
			c.SSHPTY = true
		case "--no-ssh-pty":
			c.SSHPTY = false
		case "--init":
			c.TermInit = true
		case "--no-init":
			c.TermInit = false
		case "--local":
			c.Local = true
		case "--client":
			v, err := takeValue("--client", inline)
			if err != nil {
				return nil, err
			}
			c.Client = v
		case "--server":
			v, err := takeValue("--server", inline)
			if err != nil {
				return nil, err
			}
			c.Server = v
		case "--bind-server":
			v, err := takeValue("--bind-server", inline)
			if err != nil {
				return nil, err
			}
			c.BindServer = v
		case "--experimental-remote-ip":
			v, err := takeValue("--experimental-remote-ip", inline)
			if err != nil {
				return nil, err
			}
			c.RemoteIPMode = v
		case "--key":
			v, err := takeValue("--key", inline)
			if err != nil {
				return nil, err
			}
			c.Key = v
		case "--shutdown-after-idle":
			v, err := takeValue("--shutdown-after-idle", inline)
			if err != nil {
				return nil, err
			}
			d, err := parseSeconds(v)
			if err != nil {
				return nil, err
			}
			c.IdleTimeout = d
		case "--timeout":
			v, err := takeValue("--timeout", inline)
			if err != nil {
				return nil, err
			}
			d, err := parseSeconds(v)
			if err != nil {
				return nil, err
			}
			c.ServerTimeout = d
		case "--connect-timeout", "--wait":
			v, err := takeValue(name, inline)
			if err != nil {
				return nil, err
			}
			d, err := parseSeconds(v)
			if err != nil {
				return nil, err
			}
			c.ConnectTimeout = d
		case "-e", "--echo-cancel":
			c.EchoCancel = true
		case "-c-cancel", "--cancel", "--no-cancellation":
			// Older mosh had a key-cancellation mode; 1.4 removed it.
			c.Warnings = append(c.Warnings, name+" is accepted for compatibility and has no effect")
		case "--native-ssh":
			c.NativeSSH = true
		case "--external-ssh":
			c.ExternalSSH = true
		case "--fake-proxy":
			c.Mode = ModeFakeProxy
		default:
			if strings.HasPrefix(arg, "-") && arg != "-" {
				return nil, fmt.Errorf("%w: unknown option %s", ErrUsage, arg)
			}
			positional = append(positional, arg)
			sawPositional = true
		}
	}

	if c.Mode == ModeColorCount || c.Mode == ModeFakeProxy || c.Mode == ModeInfo {
		return c, nil
	}

	if len(positional) < 1 {
		return nil, fmt.Errorf("%w: no host given", ErrUsage)
	}
	target := positional[0]
	c.Command = positional[1:]
	if c.Key != "" {
		// mosh-client style: "IP PORT" with a key from --key or MOSH_KEY.
		c.Mode = ModeDirect
		c.IP = target
		if len(c.Command) != 1 {
			return nil, fmt.Errorf("%w: direct mode wants IP and PORT", ErrUsage)
		}
		c.PortRequest = c.Command[0]
		c.Command = nil
	} else {
		c.User, c.Host = splitUserHost(target)
		if c.User == "" {
			c.User, _ = lookup(env, "USER")
			if c.User == "" {
				c.User, _ = lookup(env, "USERNAME")
			}
		}
	}
	if c.Predict != "adaptive" && c.Predict != "always" && c.Predict != "never" && c.Predict != "experimental" {
		return nil, fmt.Errorf("%w: unknown --predict mode %q", ErrUsage, c.Predict)
	}
	switch c.Family {
	case "inet", "inet6", "auto", "all", "prefer-inet", "prefer-inet6":
	default:
		return nil, fmt.Errorf("%w: unknown --family %q", ErrUsage, c.Family)
	}
	switch c.RemoteIPMode {
	case "proxy", "local", "remote":
	default:
		return nil, fmt.Errorf("%w: unknown --experimental-remote-ip %q", ErrUsage, c.RemoteIPMode)
	}
	if c.PortRequest != "" && !validPortSpec(c.PortRequest) {
		return nil, fmt.Errorf("%w: bad UDP port or range %q", ErrUsage, c.PortRequest)
	}
	return c, nil
}

func lookup(env map[string]string, key string) (string, bool) {
	if env == nil {
		env = environ()
	}
	v, ok := env[key]
	return v, ok
}

func environ() map[string]string {
	m := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.Index(kv, "="); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func splitUserHost(s string) (user, host string) {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[:i], unbracket(s[i+1:])
	}
	return "", unbracket(s)
}

func unbracket(s string) string {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1]
	}
	return s
}

func validPortSpec(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

func parseSeconds(v string) (time.Duration, error) {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("%w: %q is not a number of seconds", ErrUsage, v)
	}
	return time.Duration(f * float64(time.Second)), nil
}

// shellWords splits a command string the way the mosh wrapper's shellwords()
// does, honouring single and double quotes and backslash escapes.  It is
// deliberately small: it exists so --ssh="ssh -o ProxyJump=bastion" behaves.
func shellWords(s string) []string {
	var out []string
	var cur strings.Builder
	inSingle, inDouble, escaped, started := false, false, false, false
	flush := func() {
		if started {
			out = append(out, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
			started = true
		case r == '\\' && !inSingle:
			// Inside single quotes a backslash is literal, as in a POSIX
			// shell; inside double quotes it only escapes the five characters
			// the shell treats specially, which the default branch below
			// approximates by keeping the backslash.
			escaped = true
			started = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			started = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			started = true
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	flush()
	return out
}
