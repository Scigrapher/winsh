// Package bootstrap starts a mosh-server on a remote host and reports the
// UDP port and session key it chose -- the step mosh performs with ssh(1).
//
// Two backends are provided.  The external one execs ssh(1) exactly as mosh's
// wrapper does, so behaviour, ProxyCommand support, certificates, and
// site-specific ssh_config all keep working.  The native one uses winsh's own
// SSH client, which is what reads keys straight out of Pageant or ~/.ssh.
package bootstrap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"winsh/internal/agent"
	"winsh/internal/cli"
	"winsh/internal/keys"
	"winsh/internal/moshcrypto"
	"winsh/internal/ssh"
	"winsh/internal/textsafe"
)

// Result is what a successful bootstrap yields: everything needed to start
// talking UDP to the server.
type Result struct {
	IP   string
	Port int
	Key  moshcrypto.Key
	// ServerAddress is the host name the user typed, used for host-key
	// bookkeeping.
	ServerAddress string
	// Backend names the SSH path that produced this result.
	Backend string
}

// Options tune the bootstrap.
type Options struct {
	Verbose bool
	// Env is the environment to consult when looking for an agent, so that
	// tests and callers can drive it without touching the process.
	Env map[string]string
	// Prompt collects passwords for the native backend.
	Prompt func(label string, echo bool) (string, error)
	// ConfirmHostKey is consulted for a host that is not in known_hosts.
	// Returning true accepts the key on first use.
	ConfirmHostKey func(addr string, k keys.PubKey) bool
	// StrictHostKey refuses unknown hosts outright.
	StrictHostKey bool
	// Colors is the colour count advertised to mosh-server.
	Colors int
}

// Run starts a session on the remote host.
func Run(c *cli.Config, opt Options) (*Result, error) {
	if c.Local {
		return runLocal(c, opt)
	}
	if c.NativeSSH {
		return runNative(c, opt)
	}
	return runExternalSSH(c, opt)
}

// ---------- server command construction ----------

// serverCommandLine builds the remote command, matching what mosh's wrapper
// sends: "mosh-server new -c COLORS [-s|-i ADDR] [-p RANGE] [-l VAR=val ...]
// [-- command...]".
func serverCommandLine(c *cli.Config, opt Options, bindArg string) string {
	parts := []string{shellQuote(c.Server)}
	for _, arg := range serverArguments(c, opt, bindArg) {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

// serverArguments returns argv for mosh-server without invoking a shell.
func serverArguments(c *cli.Config, opt Options, bindArg string) []string {
	args := []string{"new"}
	colors := opt.Colors
	if colors == 0 {
		colors = ColorCount()
	}
	args = append(args, "-c", strconv.Itoa(colors))
	switch bindArg {
	case "-s":
		args = append(args, "-s")
	case "":
	default:
		args = append(args, "-i", bindArg)
	}
	if c.PortRequest != "" {
		args = append(args, "-p", c.PortRequest)
	}
	for _, kv := range localeVars() {
		args = append(args, "-l", kv)
	}
	if len(c.Command) > 0 {
		args = append(args, "--")
		args = append(args, c.Command...)
	}
	return args
}

// localeVars mirrors mosh's locale_vars(): the variables mosh-server should
// recreate on the far side.
func localeVars() []string {
	var out []string
	for _, name := range []string{"LANG", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME",
		"LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_PAPER", "LC_NAME",
		"LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION"} {
		if v := os.Getenv(name); v != "" {
			out = append(out, name+"="+v)
		}
	}
	// COLORTERM has to travel too.  -c only tells mosh-server how many colours
	// are available; a program on the far side decides whether to emit
	// 38;2;r;g;b by looking at COLORTERM.  Without this the session negotiated
	// truecolour and then never used it.
	if ct := os.Getenv("COLORTERM"); ct != "" {
		out = append(out, "COLORTERM="+ct)
	} else if ColorCount() > 256 {
		out = append(out, "COLORTERM=truecolor")
	}
	return out
}

// ColorCount answers what mosh-client -c answers: the colour count of the
// local terminal.  Windows Terminal and ConHost both advertise 256 colours
// (and truecolour), so the answer is 256 unless TERM says otherwise.
func ColorCount() int {
	term := strings.ToLower(os.Getenv("TERM"))
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	switch {
	// COLORTERM is the de-facto truecolour flag and TERM rarely says it, so
	// checking only TERM used to report 256 on a terminal that does 24-bit;
	// mosh-server then told the far side it could not, and programs emitted
	// 8-or-16-colour SGR no matter what winsh itself could render.
	case strings.Contains(ct, "truecolor"), strings.Contains(ct, "24bit"),
		strings.Contains(ct, "24-bit"):
		return 16777216
	case strings.Contains(term, "truecolor"), strings.Contains(term, "direct"):
		return 16777216
	case term == "":
		return 256
	case strings.Contains(term, "256"):
		return 256
	case strings.Contains(term, "88"):
		return 88
	case strings.Contains(term, "mono"), strings.Contains(term, "tty"):
		return 8
	}
	return 256
}

// shellQuote quotes one argument for the remote POSIX shell, the way mosh's
// shell_quote does.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r == '-' || r == '.' || r == '/' || r == '_' || r == ':' ||
			r == '=' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------- external ssh ----------

var (
	reMOSHIP      = regexp.MustCompile(`^MOSH IP (\S+)\s*$`)
	reSSHConn     = regexp.MustCompile(`^MOSH SSH_CONNECTION (\S+) (\S+) (\S+) (\S+)\s*$`)
	reMOSHConnect = regexp.MustCompile(`^MOSH CONNECT (\d+) ([A-Za-z0-9/+]{22})\s*$`)
)

func runExternalSSH(c *cli.Config, opt Options) (*Result, error) {
	sshCmd := c.SSHCommand
	if len(sshCmd) == 0 {
		sshCmd = []string{"ssh"}
	}
	args := []string{"-n"}
	if pipe := pageantIdentityAgent(opt); pipe != "" {
		defer func() {
			if opt.Verbose {
				fmt.Fprintf(os.Stderr, "winsh: telling ssh to use Pageant via IdentityAgent=%s\n", pipe)
			}
		}()
		args = append(args, "-o", "IdentityAgent="+pipe)
	}
	if c.SSHPTY {
		args = append(args, "-tt")
	}
	for _, o := range c.SSHOptions {
		args = append(args, "-o", o)
	}
	if c.SSHPort != 0 {
		args = append(args, "-p", strconv.Itoa(c.SSHPort))
	}
	if c.ProxyCommand != "" {
		args = append(args, "-o", "ProxyCommand="+c.ProxyCommand)
	}
	switch c.Family {
	case "inet":
		args = append(args, "-4")
	case "inet6":
		args = append(args, "-6")
	}
	bindArg := bindArgument(c)
	target := c.Host
	if c.User != "" {
		target = c.User + "@" + c.Host
	}
	cmdLine := serverCommandLine(c, opt, bindArg)
	args = append(args, target, "--", cmdLine)

	if opt.Verbose {
		fmt.Fprintf(os.Stderr, "winsh: running %s %s\n", strings.Join(sshCmd, " "), strings.Join(args, " "))
	}
	cmd := exec.Command(sshCmd[0], args[1:]...)
	cmd.Stdin = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("winsh: ssh pipe: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("winsh: could not run %s: %w (use --ssh=COMMAND to choose another client, or --native-ssh)", sshCmd[0], err)
	}

	res, err := parseBootstrap(stdout, c, opt)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	// The ssh process must stay alive only long enough for mosh-server to
	// start; mosh itself kills it right after the CONNECT line.
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	res.Backend = "external ssh"
	return res, nil
}

// pageantIdentityAgent returns a pipe name to hand to an external ssh.exe as
// its IdentityAgent, or "" when there is nothing useful to point it at.
//
// This exists because Windows OpenSSH only knows to look for its own agent at
// \\\.\pipe\openssh-ssh-agent.  Pageant listens on a deliberately unguessable
// per-user name, so without this a user whose keys live only in Pageant cannot
// authenticate at all through the external-ssh bootstrap, which is winsh's
// default path.  PuTTY solves the same problem for ssh.exe with
// "pageant --openssh-config"; winsh has to do it itself because the bootstrap
// runs before any of winsh's own agent code is involved.
//
// The path is taken from a connection this process actually opened and, for a
// discovered pipe, whose ownership it actually verified.  Resolving the name
// independently here would hand the session's signature requests to whatever
// pipe happens to carry the name, which is precisely the squatting attack the
// odd name exists to prevent.
func pageantIdentityAgent(opt Options) string {
	env := opt.Env
	if env == nil {
		env = map[string]string{"SSH_AUTH_SOCK": os.Getenv("SSH_AUTH_SOCK")}
	}
	if v := env["SSH_AUTH_SOCK"]; v != "" {
		// ssh.exe reads SSH_AUTH_SOCK itself; do not second-guess an agent the
		// user configured deliberately.
		return ""
	}
	cl, _, err := agent.ConnectFirstReachable(env)
	if err != nil {
		return ""
	}
	defer cl.Close()
	// A successful connect is the gate, deliberately not a successful key
	// listing.  ConnectFirst already bounded the pipe wait and, for a
	// discovered pipe, proved we are talking to a pipe that we own; that is the
	// part worth insisting on.  Requiring Identities() to succeed used to
	// disable this bridge whenever the agent declined to enumerate -- which is
	// exactly what Pageant does -- and silently cost the user their only
	// working authentication path.  If the pipe turns out to be unhelpful,
	// ssh.exe falls back on its own.
	if !strings.Contains(strings.ToLower(cl.Name()), "pageant") {
		// Any other agent is one ssh.exe would have found on its own.
		return ""
	}
	return sshAgentPath(cl.Path())
}

// sshAgentPath rewrites a Windows named-pipe path into the spelling that
// Windows OpenSSH actually accepts.
//
// ssh.exe treats an IdentityAgent value as a POSIX-style path and re-slashes
// it, so handing it the canonical \xxx form makes it look for something that
// does not exist: "ssh_get_authentication_socket: No such file or directory",
// and authentication silently falls through to a password prompt.  The
// //./pipe/... form is the one that reaches the agent.  Observed directly
// against PuTTY Pageant: same pipe, same key, one form works and the other
// does not.
func sshAgentPath(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func bindArgument(c *cli.Config) string {
	if c.Local {
		return c.Host
	}
	switch strings.ToLower(c.BindServer) {
	case "any":
		return ""
	case "ssh", "":
		return "-s"
	default:
		return c.BindServer
	}
}

func parseBootstrap(r io.Reader, c *cli.Config, opt Options) (*Result, error) {
	return parseBootstrapTo(r, c, opt, os.Stderr)
}

func parseBootstrapTo(r io.Reader, c *cli.Config, opt Options, status io.Writer) (*Result, error) {
	var ip, sshConnIP string
	var port int
	var key moshcrypto.Key
	gotKey := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := reMOSHIP.FindStringSubmatch(line); m != nil {
			if ip != "" {
				return nil, errors.New("winsh: server tried to redefine MOSH IP")
			}
			ip = m[1]
			continue
		}
		if m := reSSHConn.FindStringSubmatch(line); m != nil {
			sshConnIP = m[3]
			continue
		}
		if m := reMOSHConnect.FindStringSubmatch(line); m != nil {
			p, err := strconv.Atoi(m[1])
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("winsh: bad MOSH CONNECT port %q", m[1])
			}
			k, err := moshcrypto.ParseKey(m[2])
			if err != nil {
				return nil, fmt.Errorf("winsh: bad MOSH CONNECT key: %w", err)
			}
			port, key, gotKey = p, k, true
			break
		}
		if strings.Contains(line, "Bad UDP port") && c.PortRequest != "" {
			return nil, errors.New("winsh: the server does not support the UDP port range option")
		}
		if line != "" {
			// Anything else is the user's problem to see: shell chatter,
			// motd, or an error from ssh.
			fmt.Fprintln(status, textsafe.Line(line, 4096))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("winsh: reading from ssh: %w", err)
	}
	if !gotKey {
		return nil, errors.New("winsh: did not find the mosh server startup message " +
			"(is mosh installed on the server, and does the account allow logins?)")
	}
	if ip == "" {
		ip = sshConnIP
	}
	if ip == "" {
		// Fall back to resolving the name ourselves, which is what
		// --experimental-remote-ip=local does.
		addrs, err := resolve(c.Host, c.Family)
		if err != nil || len(addrs) == 0 {
			return nil, errors.New("winsh: could not determine the server's IP address " +
				"(try --experimental-remote-ip=remote or =local)")
		}
		ip = addrs[0]
	}
	return &Result{IP: ip, Port: port, Key: key, ServerAddress: c.Host}, nil
}

// ---------- native ssh ----------

func runNative(c *cli.Config, opt Options) (*Result, error) {
	signers, notes, err := CollectSigners(nil)
	if err != nil {
		return nil, err
	}
	for _, n := range notes {
		if opt.Verbose {
			fmt.Fprintln(os.Stderr, "winsh:", textsafe.Line(n, 4096))
		}
	}
	port := 22
	if c.SSHPort != 0 {
		port = c.SSHPort
	}
	addrs, err := resolve(c.Host, c.Family)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		cfg := ssh.Config{
			Addr:            addr,
			Host:            c.Host,
			Port:            port,
			User:            c.User,
			Signers:         signers,
			StrictHostKey:   opt.StrictHostKey,
			HostKeyCallback: opt.ConfirmHostKey,
			Verbose:         opt.Verbose,
			Prompt:          opt.Prompt,
			Timeout:         20 * time.Second,
			Banner:          func(s string) { printRemoteBanner(os.Stderr, s) },
		}
		client, err := ssh.Connect(cfg)
		if err != nil {
			lastErr = err
			continue
		}
		res, err := bootstrapOverClient(client, c, opt, addr)
		client.Close()
		if err != nil {
			lastErr = err
			continue
		}
		res.Backend = "native ssh"
		return res, nil
	}
	if lastErr == nil {
		lastErr = errors.New("winsh: no address to connect to")
	}
	return nil, lastErr
}

func bootstrapOverClient(client *ssh.Client, c *cli.Config, opt Options, addr string) (*Result, error) {
	ch, err := client.OpenSession()
	if err != nil {
		return nil, fmt.Errorf("winsh: ssh channel: %w", err)
	}
	defer ch.Close()
	if c.SSHPTY {
		cols, rows := 80, 24
		if err := ch.RequestPty(os.Getenv("TERM"), cols, rows); err != nil {
			return nil, err
		}
	}
	for _, kv := range localeVars() {
		if i := strings.Index(kv, "="); i > 0 {
			_ = ch.SetEnv(kv[:i], kv[i+1:])
		}
	}
	bindArg := bindArgument(c)
	if bindArg == "-s" {
		// The native client knows the peer address, so hand it to mosh-server
		// directly instead of relying on SSH_CONNECTION.
		bindArg = addr
	}
	if bootCmd := serverCommandLine(c, opt, bindArg); opt.Verbose {
		fmt.Fprintf(os.Stderr, "winsh: native exec: %s\n", bootCmd)
	}

	if err := ch.Exec(serverCommandLine(c, opt, bindArg)); err != nil {
		return nil, err
	}
	// The bootstrap output is a small amount of text ending in the CONNECT
	// line; read it with a deadline.
	done := make(chan *bootstrapRead, 1)
	go func() {
		// The error has to travel with the result. Swallowing it here turns
		// every failure into the same unhelpful "did not report a session",
		// which is exactly the sort of message that costs an evening.
		res, err := readBootstrapFrom(ch)
		done <- &bootstrapRead{res: res, err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		if r.res == nil || r.res.Port == 0 {
			return nil, errors.New("winsh: mosh-server did not report a session")
		}
		r.res.IP = addr
		return r.res, nil
	case <-time.After(30 * time.Second):
		if se := ch.Stderr(); len(se) > 0 {
			return nil, fmt.Errorf("winsh: timed out waiting for mosh-server to start; it wrote to stderr: %s",
				textsafe.Line(strings.TrimSpace(string(se)), 4096))
		}
		if len(ch.StdoutBuffered()) > 0 {
			return nil, fmt.Errorf("winsh: timed out waiting for mosh-server to start; it wrote %q to stdout", ch.StdoutBuffered())
		}
		return nil, errors.New("winsh: timed out waiting for mosh-server to start")
	}
}

// readBootstrapFrom consumes channel data until the CONNECT line appears.
type chunkReader struct {
	ch  *ssh.Channel
	buf []byte
}

const maxBootstrapLine = 64 * 1024

func (r *chunkReader) append(data []byte) error {
	if len(r.buf)+len(data) > maxBootstrapLine {
		return fmt.Errorf("winsh: bootstrap output line exceeds %d bytes", maxBootstrapLine)
	}
	r.buf = append(r.buf, data...)
	return nil
}

func (r *chunkReader) ReadLine() (string, error) {
	for {
		if i := indexByte(r.buf, '\n'); i >= 0 {
			line := string(r.buf[:i])
			r.buf = r.buf[i+1:]
			return strings.TrimRight(line, "\r"), nil
		}
		var tmp [4096]byte
		n, err := r.ch.Read(tmp[:])
		if n > 0 {
			if appendErr := r.append(tmp[:n]); appendErr != nil {
				return "", appendErr
			}
		}
		if err != nil {
			if len(r.buf) == 0 {
				return "", err
			}
			line := string(r.buf)
			r.buf = nil
			return line, nil
		}
	}
}

// bootstrapRead carries the outcome of reading the mosh-server startup
// messages, so that the failure explains itself instead of collapsing into a
// nil result.
type bootstrapRead struct {
	res *Result
	err error
}

func readBootstrapFrom(ch *ssh.Channel) (*Result, error) {
	r := &chunkReader{ch: ch}
	res := &Result{}
	gotKey := false
	for {
		line, err := r.ReadLine()
		if err != nil && line == "" {
			if gotKey {
				return res, nil
			}
			// Surface whatever the server wrote to stderr.
			if se := ch.Stderr(); len(se) > 0 {
				return nil, fmt.Errorf("winsh: mosh-server failed: %s",
					textsafe.Line(strings.TrimSpace(string(se)), 4096))
			}
			return nil, fmt.Errorf("winsh: could not start mosh-server: %w", err)
		}
		if m := reMOSHConnect.FindStringSubmatch(line); m != nil {
			p, e := strconv.Atoi(m[1])
			if e != nil {
				return nil, fmt.Errorf("winsh: bad MOSH CONNECT port")
			}
			k, e := moshcrypto.ParseKey(m[2])
			if e != nil {
				return nil, e
			}
			res.Port, res.Key, gotKey = p, k, true
			return res, nil
		}
		if m := reMOSHIP.FindStringSubmatch(line); m != nil {
			res.IP = m[1]
			continue
		}
		if line != "" {
			fmt.Fprintln(os.Stderr, textsafe.Line(line, 4096))
		}
		if !strings.Contains(line, "MOSH") && len(line) > 0 && r.ch == nil {
			break
		}
	}
	return nil, errors.New("winsh: mosh-server did not report a session")
}

func printRemoteBanner(w io.Writer, s string) {
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		fmt.Fprintln(w, "winsh: remote banner:", textsafe.Line(line, 4096))
	}
}

func indexByte(b []byte, sep byte) int {
	for i, x := range b {
		if x == sep {
			return i
		}
	}
	return -1
}

// ---------- local mode ----------

func runLocal(c *cli.Config, opt Options) (*Result, error) {
	// --local runs the server command directly, no ssh: useful for testing a
	// server build or for a loopback session on this machine.
	cmd := localServerCommand(c, opt)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("winsh: could not run %s: %w", c.Server, err)
	}
	res, err := parseBootstrap(out, c, opt)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	if res.IP == "" {
		res.IP = "127.0.0.1"
	}
	res.Backend = "local"
	_ = cmd.Process.Kill()
	return res, nil
}

func localServerCommand(c *cli.Config, opt Options) *exec.Cmd {
	return exec.Command(c.Server, serverArguments(c, opt, c.Host)...)
}

// ---------- helpers shared with the CLI ----------

// CollectSigners gathers keys from the agent (Pageant first) and then from
// ~/.ssh.
func CollectSigners(env map[string]string) ([]keys.Signer, []string, error) {
	var signers []keys.Signer
	var notes []string
	if cl, tried, err := agent.ConnectFirst(env); err == nil {
		s, err := keys.FromAgent(cl)
		if err != nil {
			notes = append(notes, "agent: "+err.Error())
		}
		signers = append(signers, s...)
		if len(s) == 0 {
			notes = append(notes, fmt.Sprintf("agent %s offered no usable keys", cl.Name()))
		}
		// The agent connection must stay open for signing, so it is not
		// closed here; the process lifetime bounds it.
		_ = tried
	} else {
		notes = append(notes, err.Error())
	}
	home, _ := os.UserHomeDir()
	paths := keys.DefaultPaths(home)
	paths = append(paths, c_extraPaths(env)...)
	fileSigners, fileNotes := keys.LoadFiles(paths)
	signers = append(signers, fileSigners...)
	notes = append(notes, fileNotes...)
	if len(signers) == 0 {
		return nil, notes, fmt.Errorf("winsh: no SSH keys available (%s)", strings.Join(notes, "; "))
	}
	return signers, notes, nil
}

func c_extraPaths(env map[string]string) []string {
	if env == nil {
		env = map[string]string{"SSH_IDENTITY": os.Getenv("SSH_IDENTITY")}
	}
	if v := env["SSH_IDENTITY"]; v != "" {
		return []string{v}
	}
	return nil
}

// resolve turns a hostname into addresses, honouring --family.  The order
// follows mosh's "prefer-inet" default so a dual-stack host behaves the same
// way it does with the reference client.
func resolve(host, family string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("winsh: resolving %s: %w", host, err)
	}
	var v4, v6 []string
	for _, a := range addrs {
		if a.IP.To4() != nil {
			v4 = append(v4, a.IP.String())
		} else {
			v6 = append(v6, a.IP.String())
		}
	}
	switch family {
	case "inet":
		if len(v4) == 0 {
			return nil, fmt.Errorf("winsh: %s has no IPv4 address", host)
		}
		return v4, nil
	case "inet6":
		if len(v6) == 0 {
			return nil, fmt.Errorf("winsh: %s has no IPv6 address", host)
		}
		return v6, nil
	case "all":
		return append(append([]string{}, v4...), v6...), nil
	case "prefer-inet6":
		return append(append([]string{}, v6...), v4...), nil
	default: // auto, prefer-inet
		if len(v4) > 0 {
			return v4, nil
		}
		if len(v6) > 0 {
			return v6, nil
		}
		return nil, fmt.Errorf("winsh: no address found for %s", host)
	}
}
