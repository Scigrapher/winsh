// Command winsh is a Windows-native mosh client: one static, memory-safe
// executable that needs no installation and speaks the mosh 1.4 protocol.
//
// Usage summary (see --help for the full list):
//
//	winsh [options] [--] [user@]host [command...]
//	winsh --key=KEY host udpport
//	winsh --show-licenses | --version | --help | --diagnostics | --self-test
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"winsh/internal/bootstrap"
	"winsh/internal/cli"
	"winsh/internal/consoleapi"
	"winsh/internal/fakeserver"
	"winsh/internal/keys"
	"winsh/internal/licenses"
	"winsh/internal/moshcrypto"
	"winsh/internal/session"
	"winsh/internal/ssh"
	"winsh/internal/state"
	"winsh/internal/textsafe"
	"winsh/internal/transport"
	"winsh/internal/vt"
)

func main() {
	// The interactive session's live set is dominated by the terminal
	// emulator and the SSP window.  A soft heap limit keeps that footprint
	// fixed even if a future change reintroduces a retention bug; it is not a
	// hard cap, so a legitimate large frame can still be served.
	debug.SetMemoryLimit(256 << 20)
	os.Exit(run(os.Args[1:], os.Environ()))
}

func run(argv []string, envv []string) int {
	env := map[string]string{}
	for _, kv := range envv {
		if i := strings.Index(kv, "="); i >= 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}
	cfg, err := cli.Parse(argv, env)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprint(os.Stderr, cli.Usage(progName()))
		return 1
	}
	if len(cfg.Warnings) > 0 && cfg.Mode == cli.ModeInteractive {
		for _, w := range cfg.Warnings {
			fmt.Fprintln(os.Stderr, "winsh: warning:", w)
		}
	}

	switch cfg.Mode {
	case cli.ModeInfo:
		return runInfo(cfg, env)
	case cli.ModeColorCount:
		fmt.Println(bootstrap.ColorCount())
		return 0
	case cli.ModeFakeProxy:
		return runFakeProxy(argv)
	case cli.ModeDirect:
		return runDirect(cfg)
	default:
		return runInteractive(cfg, env)
	}
}

func progName() string {
	base := cli.Program
	if len(os.Args) > 0 {
		if i := strings.LastIndexAny(os.Args[0], `\/`); i >= 0 {
			base = os.Args[0][i+1:]
		}
	}
	return base
}

func runInfo(cfg *cli.Config, env map[string]string) int {
	if cfg.ShowSelfTest {
		return selfTest()
	}
	switch {
	case cfg.ShowHelp:
		fmt.Print(cli.Usage(progName()))
		return 0
	case cfg.ShowVersion:
		fmt.Println(cli.VersionBanner(progName()))
		return 0
	case cfg.ShowLicenses:
		fmt.Print(licenses.Report())
		return 0
	case cfg.ShowKeys:
		entries, probes, notes := keys.Inventory(env, "")
		fmt.Print(keys.FormatInventory(entries, probes, notes))
		return 0
	case cfg.Diag:
		fmt.Printf("%s %s\n", cli.Program, cli.Version)
		fmt.Printf("go backend (AES):   %s\n", moshcrypto.BackendName())
		fmt.Printf("mosh cipher suite:  AES-128-OCB, 96-bit nonces, 128-bit tags\n")
		fmt.Printf("mosh protocol:      version %d\n", 2)
		fmt.Printf("transport MTU:      %d bytes per datagram\n", 1280-20-8)
		fmt.Printf("screen limits:      %dx%d cells\n", vt.MaxCols, vt.MaxRows)
		fmt.Printf("console:            win32 console API (kernel32)\n")
		// Report the geometry the session would actually negotiate, because
		// "the terminal ignores my window size" is otherwise invisible from the
		// outside: it looks identical whether Size() returned the viewport, the
		// screen buffer, or nothing at all and fell back to 80x24.
		if con, err := consoleapi.Open(); err == nil {
			if cw, rh, ok := con.Size(); ok {
				fmt.Printf("console size:       %dx%d cells (detected)\n", cw, rh)
			} else {
				fmt.Printf("console size:       80x24 (no console detected; using the default)\n")
			}
		}
		fmt.Printf("entropy:            BCryptGenRandom (system preferred RNG)\n")
		return 0
	}
	fmt.Print(cli.Usage(progName()))
	return 0
}

// ---------- direct mode (mosh-client replacement) ----------

func runDirect(cfg *cli.Config) int {
	key, err := moshcrypto.ParseKey(cfg.Key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winsh:", err)
		return 1
	}
	port, err := strconv.Atoi(cfg.PortRequest)
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "winsh: bad UDP port %q\n", cfg.PortRequest)
		return 1
	}
	ip := cfg.IP
	if ip == "" {
		ip = cfg.Host
	}
	return connectAndRun(cfg, ip, port, key)
}

// ---------- interactive mode (mosh replacement) ----------

func runInteractive(cfg *cli.Config, env map[string]string) int {
	opt := bootstrap.Options{
		Verbose:        cfg.Verbose,
		Env:            env,
		Colors:         bootstrap.ColorCount(),
		StrictHostKey:  true,
		ConfirmHostKey: confirmHostKey,
		Prompt:         makePrompt(),
	}
	res, err := bootstrap.Run(cfg, opt)
	if err != nil {
		fmt.Fprintln(os.Stderr, textsafe.Terminal(err.Error(), 16*1024))
		return 1
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "winsh: server at %s:%d via %s, key accepted\n",
			textsafe.Line(res.IP, 256), res.Port, res.Backend)
	}
	return connectAndRun(cfg, res.IP, res.Port, res.Key)
}

// connectAndRun is the shared tail: build the UDP transport and run the
// interactive session.
func connectAndRun(cfg *cli.Config, ip string, port int, key moshcrypto.Key) int {
	remote := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	if remote.IP == nil {
		addrs, err := net.LookupIP(ip)
		if err != nil || len(addrs) == 0 {
			fmt.Fprintf(os.Stderr, "winsh: cannot resolve %s: %v\n", textsafe.Line(ip, 1024), err)
			return 1
		}
		remote.IP = addrs[0]
	}
	con, err := transport.NewClientConnection(key, remote, transport.ConnOptions{Verbose: cfg.Verbose})
	if err != nil {
		fmt.Fprintln(os.Stderr, "winsh:", err)
		return 1
	}
	defer con.Close()

	console, err := consoleapi.Open()
	if err != nil && cfg.Verbose {
		fmt.Fprintf(os.Stderr, "winsh: %v (continuing without a console)\n", err)
		console = nil
	}
	cols, rows := 80, 24
	if console != nil {
		if c, r, ok := console.Size(); ok {
			cols, rows = c, r
		}
	}
	tr := transport.NewTransport(con, &state.UserStream{}, vt.NewTerminalState(cols, rows))
	tr.Sender.SetSendDelay(time.Millisecond)

	titlePrefix := "[winsh] "
	if cfg.TitleNoPrefix {
		titlePrefix = ""
	}
	escKey := cfg.EscapeKey
	if cfg.NoEscapeKey {
		escKey = -1
	}
	cl := session.New(console, tr, cols, rows, session.Options{
		Predict:           cfg.Predict,
		PredictOverwrite:  cfg.PredictOver,
		Verbose:           cfg.Verbose,
		NoTermInit:        !cfg.TermInit,
		TitlePrefix:       titlePrefix,
		EscapeKey:         escKey,
		HaveRemoteCommand: len(cfg.Command) > 0,
		ConnectTimeout:    cfg.ConnectTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ServerTimeout:     cfg.ServerTimeout,
		ServerHost:        ip,
		ServerPort:        port,
	})

	if console != nil {
		console.InstallRestoreOnExit()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cl.Stop()
	}()

	runErr := cl.Run()
	// Release the console reader even on the paths that never see a signal.
	// Without this the reader goroutine stays parked in ReadConsoleInputW and
	// a later Stop() has to time out waiting for it.
	cl.Stop()
	if console != nil {
		console.Restore()
	}
	if cfg.DumpScreen {
		if lines, err := cl.DumpScreen(); err == nil {
			for _, l := range lines {
				fmt.Println(l)
			}
		}
	}
	fmt.Println("[winsh is exiting.]")
	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
		// A send-side failure usually precedes a dropped session by several
		// seconds, so surface it alongside the terminal error: "connection
		// reset by peer" explains "nothing received from server" that a plain
		// timeout does not.
		if e := cl.LastTransportError(); e != "" && e != runErr.Error() {
			fmt.Fprintln(os.Stderr, "winsh: last transport error:", e)
		}
		return 1
	}
	if e := cl.LastTransportError(); e != "" && cfg.Verbose {
		fmt.Fprintln(os.Stderr, "winsh: last transport error:", e)
	}
	return 0
}

// ---------- --fake-proxy (mosh's ProxyCommand helper) ----------

func runFakeProxy(argv []string) int {
	// mosh invokes: mosh --family=X --fake-proxy -- %h %p
	var rest []string
	seen := false
	for _, a := range argv {
		if seen {
			rest = append(rest, a)
			continue
		}
		if a == "--" {
			seen = true
		}
	}
	if len(rest) < 2 {
		fmt.Fprintln(os.Stderr, "winsh: --fake-proxy wants HOST PORT")
		return 1
	}
	host, port := rest[0], rest[1]
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 15*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winsh: --fake-proxy: %v\n", err)
		return 1
	}
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		fmt.Printf("MOSH IP %s\n", ta.IP.String())
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(conn, os.Stdin); conn.Close(); done <- struct{}{} }()
	go func() { io.Copy(os.Stdout, conn); done <- struct{}{} }()
	<-done
	return 0
}

// ---------- prompt helpers ----------

func makePrompt() func(string, bool) (string, error) {
	return func(label string, echo bool) (string, error) {
		fmt.Fprint(os.Stderr, label+": ")
		con, err := consoleapi.Open()
		if err != nil || !echo {
			if con != nil {
				return con.ReadLineNoEcho()
			}
			return "", errors.New("winsh: no console available for the password prompt")
		}
		var s string
		if _, err := fmt.Fscanln(os.Stdin, &s); err != nil {
			return "", err
		}
		return s, nil
	}
}

// confirmHostKey implements trust-on-first-use.  An unknown host is a real
// security decision, so it is put to the user explicitly rather than silently
// accepted, and the fingerprint is shown in the same shape ssh shows it.
func confirmHostKey(addr string, k keys.PubKey) bool {
	fmt.Fprintf(os.Stderr,
		"winsh: The authenticity of host '%s' cannot be established.\n"+
			"     %s key fingerprint is %s\n"+
			"Accept and remember this host key? [y/N] ",
		textsafe.Line(addr, 1024), k.Algo, k.Fingerprint())
	answer, err := makePrompt()("y or n", true)
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		files, _ := knownHostFiles()
		if err := ssh.AppendKnownHost(files, addr, 22, k); err != nil {
			fmt.Fprintln(os.Stderr, "winsh: could not save the host key; accepted for this session only:", err)
		}
		return true
	}
	return false
}

func knownHostFiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return []string{home + "\\.ssh\\known_hosts"}, nil
}

// ---------- self test ----------

// selfTest exercises the whole client stack against winsh's own fake mosh
// server on the loopback interface: key exchange framing, SSP, the cipher
// suite, and the terminal emulator.  It needs no network and no server.
func selfTest() int {
	fmt.Println("winsh self-test")
	steps := []struct {
		name string
		fn   func() error
	}{
		{"AES-128-OCB against published vectors", testOCB},
		{"session round trip over loopback UDP", testSessionLoopback},
		{"terminal emulator frame diffs", testFrameDiff},
	}
	fail := 0
	for _, s := range steps {
		start := time.Now()
		if err := s.fn(); err != nil {
			fmt.Printf("  FAIL  %-40s %v\n", s.name, err)
			fail++
			continue
		}
		fmt.Printf("  ok    %-40s %v\n", s.name, time.Since(start).Round(time.Millisecond))
	}
	if fail > 0 {
		fmt.Printf("%d check(s) failed\n", fail)
		return 1
	}
	fmt.Println("all checks passed")
	return 0
}

func testOCB() error {
	key, err := moshcrypto.NewKey()
	if err != nil {
		return err
	}
	s, err := moshcrypto.NewSession(key)
	if err != nil {
		return err
	}
	defer s.Destroy()
	msg := []byte("the quick brown fox jumps over the lazy dog")
	for i := 0; i < 1000; i++ {
		dg, err := s.Encrypt(uint64(i), msg)
		if err != nil {
			return err
		}
		if len(dg) != len(msg)+moshcrypto.NonceWordLength+moshcrypto.TagSize {
			return fmt.Errorf("unexpected datagram length %d", len(dg))
		}
		seq, out, err := s.Decrypt(dg)
		if err != nil {
			return fmt.Errorf("decrypt at %d: %w", i, err)
		}
		if seq != uint64(i) || string(out) != string(msg) {
			return fmt.Errorf("round trip mismatch at %d", i)
		}
	}
	dg, _ := s.Encrypt(5000, msg)
	dg[len(dg)-1] ^= 0x40
	if _, _, err := s.Decrypt(dg); err == nil {
		return errors.New("tampered packet was accepted")
	}
	return nil
}

func testSessionLoopback() error {
	key, err := moshcrypto.NewKey()
	if err != nil {
		return err
	}
	lo := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	srv, err := fakeserver.New(key, lo, fakeserver.Options{Cols: 40, Rows: 6, Echo: true})
	if err != nil {
		return err
	}
	defer srv.Close()
	con, err := transport.NewClientConnection(key, lo, transport.ConnOptions{})
	if err != nil {
		return err
	}
	con.SetRemote(srv.Addr())
	srv.Attach(con.LocalAddr())
	defer con.Close()

	tr := transport.NewTransport(con, &state.UserStream{}, vt.NewTerminalState(40, 6))
	tr.Sender.SetSendDelay(time.Millisecond)
	cl := session.New(nil, tr, 40, 6, session.Options{
		Predict: session.PredictNever, EscapeKey: -1, NoTermInit: true, ServerPort: srv.Port(),
	})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := srv.ServeOnce(time.Now().Add(2 * time.Millisecond)); err != nil {
				return
			}
		}
	}()
	go func() { _ = cl.Run() }()
	defer cl.Stop()

	cl.PushInput([]byte("hello winsh\r"))
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if txt, err := cl.LastRenderedText(); err == nil && strings.Contains(txt, "hello winsh") {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errors.New("typed input never came back from the server")
}

func testFrameDiff() error {
	st := vt.NewTerminalState(40, 6)
	lines := []string{"alpha", "beta", "gamma", "delta"}
	for i, l := range lines {
		st.Feed([]byte(fmt.Sprintf("\x1b[%d;1H%s", i+1, l)))
	}
	before := st.Clone().(*vt.TerminalState)
	st.Feed([]byte("\x1b[2J\x1b[1;1HZebra \x1b[1;31mRED\x1b[0m\r\n\x1b[3;5Htabbed\tout\r\n"))
	diff := st.DiffFrom(before)
	replayed := before.Clone().(*vt.TerminalState)
	if err := replayed.ApplyString(diff); err != nil {
		return err
	}
	if !replayed.Equal(st) {
		return errors.New("rendered frame diff did not reproduce the terminal state")
	}
	fresh := vt.NewTerminalState(40, 6)
	if err := fresh.ApplyString(st.InitDiff()); err != nil {
		return err
	}
	if !fresh.Equal(st) {
		return errors.New("init diff did not reproduce the terminal state")
	}
	return nil
}
