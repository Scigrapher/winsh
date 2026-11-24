# winsh — a Windows-native mosh client

winsh is a drop-in replacement for the `mosh` client, written in Go for
Windows.  It is one static, self-contained `.exe`: no installer, no runtime,
no administrator rights, no third-party libraries.

```
> winsh user@server.example.com
user@server:~$
 Ctrl-^ then "." quits; Ctrl-^ Ctrl-Z detaches (--help lists the commands)
```

That last line is the notice winsh paints, reverse-video, on the bottom row for the
first few seconds of an interactive session.  It is the only place the hotkey is
mentioned at runtime, which is why it names the key in words rather than as a raw
byte.

It speaks the mosh 1.4 protocol — SSP over UDP with the AES-128-OCB cipher
suite — so it interoperates with the standard `mosh-server` on any Linux or
BSD box, and it survives the things that kill an SSH session: sleep, IP
changes, NAT re-binding, and hours-long blackholes.

---

## Status

| Requirement | State |
|---|---|
| Memory-safe language | **Go 1.27** (no cgo, no unsafe pointer arithmetic outside the syscall layer) |
| Single standalone binary | **Yes** — `bin\winsh.exe`, ~4 MB with `-ldflags "-s -w"`, statically linked, no installer |
| Drop-in for `mosh` | **Yes** for the mosh 1.4 option set, plus the legacy 1.3 options users still type |
| Windows libraries for crypto/networking | **Yes** — CNG `bcrypt.dll` (AES, RNG), Winsock via Go's `net`, kernel32 console API |
| Third-party dependencies | **Zero** — Go standard library only (`go.mod` has no requirements) |
| Pageant + `~/.ssh` keys | **Yes** — `internal/agent` speaks the SSH agent protocol to Pageant and `ssh-agent`, discovers Pageant's per-user pipe by name and refuses any it cannot prove you own; `internal/keys` loads unencrypted keys from `~/.ssh`; `--list-keys` shows the whole inventory |
| Licensing | **GPLv3** or later (`LICENSE`, or `--show-licenses` for the text) |
| Security posture | Host key verification on by default, SHA-1 host keys refused, no CBC/RC4/MD5, constant-time tag comparison, replay protection, bounded allocations on hostile input |

The protocol work is verified, not assumed: OCB is checked against the
published RFC 7253 / draft-krovetz-ocb-03 vectors, the transport is tested over
real UDP with injected packet loss, and the terminal emulator is tested with a
300-round randomised property test that replays every rendered frame diff and
compares the result cell by cell.

It has also been driven against a real server: an Ubuntu host running
OpenSSH_9.6p1, authenticating with an RSA key held only in Pageant, on both
backends.

```
> go test ./...
ok      winsh/internal/moshcrypto      # AES-128-OCB vs published vectors, both backends
ok      winsh/internal/transport       # SSP: fragmentation, retransmit, loss, roaming, replay
ok      winsh/internal/vt              # terminal emulator + frame-diff round trip (300 rounds)
ok      winsh/internal/session         # end-to-end client vs a fake mosh-server on loopback
ok      winsh/internal/keys            # real ssh-keygen keys: parse, sign, verify, refuse
ok      winsh/internal/agent           # agent protocol against an in-process agent, pipe trust
ok      winsh/internal/ssh             # SSH packet layer, negotiation and key encoding vs the wire
ok      winsh/internal/ssp             # protobuf messages mosh servers expect
ok      winsh/internal/wire            # protobuf wire codec
ok      winsh/internal/cli             # mosh-compatible option parsing
```

---

## Building

```powershell
go build -o bin\winsh.exe .\cmd\winsh
go test ./...
.\bin\winsh.exe --self-test          # protocol + crypto + terminal smoke test
```

No network access, C compiler, or module download is required: `go.mod` has
zero requirements.

---

## Using it

### Normal use (same as mosh)

```powershell
winsh user@host
winsh user@host -- htop              # run one command under mosh
winsh -p 62000:62010 host            # pin the server-side UDP range
winsh --ssh="ssh -o ProxyJump=bastion" host
winsh --predict=always host          # always local-echo keystrokes
winsh --family=inet --no-init host
```

Every option mosh 1.4's wrapper accepts is accepted here with the same meaning:
`--client --server --predict -a -n -o --family -4 -6 -p --port --ssh
--no-ssh-pty --no-init --local --bind-server --experimental-remote-ip
--ssh-proxy-command --fake-proxy --help --version`.

The options older mosh releases accepted still work too: `--key`, `--ssh-port`,
`--udp-port`, `--avoid-udp-port`, `--shutdown-after-idle`, `--timeout`,
`--connect-timeout/--wait`, `-e/--echo-cancel`.  Prediction and echo
reconciliation are built in; `-e` is accepted as a compatibility spelling and
does not change the selected `--predict` policy.

winsh adds:

| Option | Meaning |
|---|---|
| `--show-licenses` | Full license/attribution report for the binary and the protocol it speaks |
| `--diagnostics` | Which crypto backend, protocol version, MTU, and screen limits are in use |
| `--self-test` | Runs the protocol, crypto, and terminal checks locally |
| `--native-ssh` | Use winsh's own SSH client for the bootstrap (see below) |
| `--external-ssh` | Force the external `ssh.exe` bootstrap (the default, like mosh) |
| `-v`, `--verbose` | Per-packet and bootstrap diagnostics |
| `--dump-screen` | Print the final screen text on exit |
| `--no-escape-key` | Disable the `Ctrl-^` control prefix entirely |

### Session commands (the escape key)

winsh keeps mosh's hotkey grammar exactly.  `Ctrl-^` -- which is **Ctrl+Shift+6**
on a US keyboard -- introduces a command, and the next key chooses the action:

| Keystrokes | Action |
|---|---|
| `Ctrl-^` then `.` | Quit: mosh's graceful shutdown handshake, then the console is restored |
| `Ctrl-^` then `Ctrl-Z` | Detach.  Your programs keep running on the server; press Enter to reattach over a fresh UDP port.  Windows has no job control, so this is the stand-in for mosh's suspend |
| `Ctrl-^` then `^` | Type a literal `Ctrl-^` |
| `Ctrl-^` then any other key | Send both bytes to the server untouched |
| `Ctrl-L` | Repaint the screen |

Because `Ctrl-^` is a control character it arms **anywhere**, mid-line, with no
Enter required first.  That is mosh's rule -- `stmclient.h` sets
`escape_requires_lf(false)` for control escapes and `true` only for printable
ones -- and it is the difference between a discoverable exit and a session that
looks unexitable.  A *printable* escape key, if you configure one, does require a
newline first, again exactly as in mosh, so that typing it in ordinary input stays
possible.

The command hint appears on the bottom row the moment you press `Ctrl-^`, and
`winsh --help` repeats the whole grammar.

If your terminal eats Ctrl+Shift+6 (some settings bind Ctrl+Shift+digit to tab
switching), there are two ways out:

```powershell
$env:MOSH_ESCAPE_KEY="~"        # a different escape key, mosh's own rules:
                                # 1..127, empty disables it, and Ctrl-C, Ctrl-D,
                                # Ctrl-L, CR and LF are refused
winsh --no-escape-key host      # no escape key at all; every byte goes to the server
```

With the escape key off you still get `Ctrl-C` and `Ctrl-D` delivered to the
remote shell, `Ctrl-L` still repaints, and `--shutdown-after-idle` / `--timeout`
still end the session.

### Direct mode (the `mosh-client` replacement)

```powershell
winsh --key=AAAAAAAAAAAAAAAAAAAAAA 192.0.2.10 60001
$env:MOSH_KEY="AAAAAAAAAAAAAAAAAAAAAA"; winsh 192.0.2.10 60001
```

`mosh-client`'s own calling convention (`-c` for the colour count, `-# ARGS |`
for the wrapper echo) is honoured, so scripts that call the internals keep
working.

### Keys, Pageant, and the two SSH backends

The bootstrap step ("log in over SSH and run `mosh-server`") has two backends.

**External `ssh.exe` is the default.**  That is exactly what mosh's wrapper
does, so your `ssh_config`, certificates, `ProxyCommand`, agent forwarding,
and site-specific smartcards keep working unchanged.

**`--native-ssh` uses winsh's own client**, which is the path that reads keys
straight out of Pageant or `~/.ssh`:

* an agent is tried first — `$SSH_AUTH_SOCK`, then Pageant's
  `\\.\pipe\pageant.pipe`, then the Windows OpenSSH agent's pipe, then any
  `\\.\pipe\pageant.*` pipe that belongs to you.  winsh never sees the
  private key; it asks the agent to sign;
* then unencrypted keys in `~/.ssh` (`id_ed25519`, `id_ecdsa`, `id_rsa`) are
  loaded;
* RSA keys are signed as `rsa-sha2-512`/`-256`, never the deprecated SHA-1
  `ssh-rsa`;
* **host key verification is mandatory**: unknown hosts are shown as a
  `SHA256:` fingerprint and must be confirmed, changed keys are a hard error,
  and SHA-1 host keys are refused unless you pass a flag saying you mean it.

The native client was written against the published formats and then checked
against the two implementations everyone interoperates with.  The rules it had
wrong at first are worth recording, because each one produced a connection that
died silently rather than an error message:

* **`name-list` is one comma-separated string**, not a sequence of
  length-prefixed strings.  Getting this backwards produced a KEXINIT a real
  server could not read, while winsh happily agreed with itself.
* **The KEXINIT cookie is `byte[16]`**, with no length prefix.  Reading it as a
  string consumed four cookie bytes as a bogus length.
* **Each direction's cipher and MAC are chosen from the client's list**, not
  from each side's own preference.  Choosing per-side gave one direction
  `aes128-ctr` while winsh kept `aes256-ctr` for the other, and every packet
  after `NEWKEYS` was then garbage.
* **`hmac-sha2-*` is encrypt-*and*-MAC: the tag covers the plaintext.**  Only
  the `-etm@openssh.com` variants are encrypt-then-MAC, and for those the
  four-byte length field travels in the clear as authenticated data and does not
  consume keystream.  winsh prefers the ETM variants.
* **Packet padding follows whichever bytes are encrypted.**  OpenSSH drops the
  connection with a padding error unless the encrypted part of the packet is a
  multiple of the cipher block size, which differs between the two families.
* **The MAC packet counter is reset at keying only when the peer negotiated
  RFC 9142 strict key exchange.**  Classic OpenSSH keeps counting from the
  first packet of the connection; a client that always restarts at zero MACs
  its first encrypted packet with the wrong number.  winsh advertises
  `kex-strict-c-v00@openssh.com` and `ext-info-c` and honours whichever answer
  it gets.
* **`SSH_MSG_SERVICE_REQUEST("ssh-userauth")` is mandatory** before any
  authentication message, and `SSH_MSG_EXT_INFO` (type 7) can arrive wherever a
  courtesy announcement feels like.
* **Channel request replies are packets too.**  `CHANNEL_SUCCESS`/`FAILURE`
  arrive interleaved with window adjustments and data, so they are queued by the
  same reader rather than awaited on a second code path that steals the other
  one's packet.

Passphrase-protected key files are deliberately refused: load them into
Pageant or `ssh-agent` instead.  A terminal client that decrypts keys into the
Go heap cannot promise the zeroing discipline that an agent can.

### Finding Pageant, safely

`--list-keys` prints what winsh would be able to authenticate with, before you
connect anywhere:

```
winsh --list-keys
```

It reports each agent endpoint it tried (reachable, holding no keys, or why it
is unreachable), then the keys winsh can sign with by algorithm, `SHA256:`
fingerprint, source and the signature algorithms it will offer, then the keys it
found but cannot use and the reason.

Pageant deserves an explanation.  Since PuTTY 0.76 it does not listen on a
fixed name: it creates `\\.\pipe\pageant.<user>.<hash>`, where the hash comes
from your SID by a formula that has changed between releases and is in no
specification.  The classic `\\.\pipe\pageant.pipe` is a Git-for-Windows fork.
Hard-coding either one means failing to find real Pageant, so winsh enumerates
the pipe namespace and matches `pageant.*`.

Enumerating alone would be unsafe: named pipes live in a machine-global name
space, so any local program could create a pipe wearing Pageant's name and be
handed signatures to forge.  winsh therefore refuses to send a single protocol
byte on a discovered pipe until it has confirmed, via `GetSecurityInfo`, that
the pipe's **owner SID is the SID of the user running winsh** — the same check
PuTTY applies in the other direction.  Anything it cannot verify is treated as
not-owned and skipped.

Two more guards, both learned from watching a wedged agent:

* `CreateFile` is tried first and a bounded `WaitNamedPipe` runs only when it
  answers `ERROR_PIPE_BUSY`.  Waiting before opening made every absent agent
  cost the full timeout and report a two-second timeout for a pipe that had
  never been created.  An agent that is not answering is a soft failure, never
  a frozen client, and `--list-keys` now says "no agent is listening here" when
  that is what actually happened.
* The client authenticates at `SECURITY_IDENTIFICATION`, the level PuTTY's own
  client requests, because an impersonation-level connection needs the server to
  hold `SeImpersonatePrivilege`, which Pageant does not.
* One request/reply round trip is capped at 3 s.  On timeout the client is
  abandoned rather than closed, because pulling the handle out from under a
  still-blocked read is worse than leaking one handle — and discovery bounds how
  many can exist.

---

## How it works

```
cmd/winsh                 entry points: interactive, direct, --fake-proxy, --self-test, info
internal/
  cli                     mosh-compatible option parsing
  bootstrap               starts mosh-server over SSH, parses "MOSH CONNECT port key"
  ssh                     winsh's own SSH client (curve25519, AES-CTR+HMAC-SHA2, publickey)
  agent                   SSH agent protocol: Pageant named pipe + ssh-agent
  keys                    key blobs, signatures, known_hosts, private key files
  transport/
    packet.go             SSP packet: nonce carries direction+sequence, two timestamps
    connection.go         UDP sockets, RTT/RTO, port hopping, replay window, roaming
    fragment.go           zlib (RFC 1950) compression + 64-bit-id fragment reassembly
    transport.go          sender window, retransmit timers, receiver state chain
  moshcrypto/             AES-128-OCB (from RFC 7253), base64 keys, packet cipher
  cng                     bcrypt.dll bindings (AES, BCryptGenRandom)
  vt/                     VT220/xterm emulator: parser, screen model, frame renderer
  state/                  the user-input stream that SSP synchronises to the server
  predict/                per-cell speculative echo, epochs, ack reconciliation
  session/                the client event loop: input, prediction, notifications, keys
  consoleapi              win32 console: raw input, VT output, resize, Ctrl-C safety
  licenses                the license inventory printed by --show-licenses
  fakeserver              a tiny mosh-server for tests and --self-test
```

The protocol facts were verified against the mosh 1.4.0 *wire interface*
(protocol version 2, `TransportBuffers.Instruction`, direction bit in the high
bit of the OCB nonce, 22-character base64 keys, 1280-byte datagram MTU, the
20?250 ms frame rate derived from the smoothed RTT, the 3 s empty-ack interval,
the 10 s port-hop interval).  The implementation was written from the message
formats, and the published OCB test vectors were transcribed as data.  Mosh
itself is GPLv3 software; see `--show-licenses`.

### Terminal emulation

Unlike an SSH client, a mosh client must *own* the terminal model: after a
reconnect there is no byte stream to resume, so the client has to be able to
reproduce the server's screen from state alone.  `internal/vt` is a VT220/xterm
emulator (CSI/OSC/DCS parser, SGR with 16/256/truecolour, scroll regions,
origin mode, insert/delete line and character, DEC special graphics, UTF-8 with
combining marks and double-width glyphs, pending-wrap semantics, DECSCUSR,
DECTCEM) plus a renderer that turns a pair of screens into the shortest
escape-sequence diff.

The renderer's output *is* the protocol's currency, so a randomised test feeds
300 rounds of generated and random traffic through the emulator and asserts
that the diff between two states, replayed into a copy of the older one,
reproduces the newer one exactly — cell, attribute, wide-glyph flag, cursor and
all.

### Prediction and echo cancellation

Prediction is a sparse overlay over the authoritative server framebuffer, not a
separate byte stream.  Each predicted cell is tied to the outgoing SSP state
number and to a confidence epoch.  winsh models insertion and overwrite,
backspace, carriage return, and plain left/right cursor movement; modified or
unknown control sequences begin a new epoch instead of guessing.  Adaptive mode
starts with unconfirmed predictions hidden, then exposes later predictions once
the server has proved the current epoch correct.  On a slow link, outstanding
cells are underlined.

Echo cancellation is the reconciliation step.  The server's `EchoAck`
instruction says that the input frame has reached the pseudo-terminal; winsh
then compares each predicted cell with the authoritative screen.  A match
confirms the prediction epoch and retires the cell.  A mismatch kills that
epoch, or discards the whole overlay if a previously trusted prediction was
wrong.  The server screen is never overwritten by stale local text, and a
prediction is never removed merely because the transport received the input:
the delayed echo condition has to be satisfied as well.

### Colour and window geometry

Two things the user sees constantly, and both are negotiated rather than
assumed:

* **24-bit colour.** `ColorCount()` reads `COLORTERM` as well as `TERM`, so a
  truecolour terminal is advertised as 16777216 colours instead of being
  silently capped at 256, and `COLORTERM` is forwarded to `mosh-server` with
  `-l`.  That forwarding matters: `-c` only tells the far side how many colours
  exist, while programs decide whether to emit `38;2;r;g;b` by looking at
  `COLORTERM`.  The emulator parses the colon and semicolon forms of `38;2` and
  `48;2`, and `38`/`48` consume their whole operand (`5;n` or `2;r;g;b`) rather
  than only their own parameter: those operand digits are colour data, and
  reading them back as SGR codes is how a gradient whose components include a
  zero came to be painted with a reset pen.  The renderer then emits the colour
  it parsed unchanged, so a truecolour cell is not flattened to the palette on
  the way back out, and every frame opens with a rendition reset -- a frame
  diff restates the pen only when it believes the pen changed, so a frame that
  started on a terminal still wearing the previous frame's colour would
  repaint cells with the wrong one.  `--diagnostics` prints the count that
  would be negotiated.
* **Window size.** The session reports the *viewport*, not the screen buffer:
  with scrollback the buffer is much taller than the window, and the event
  Windows actually delivers (`WINDOW_BUFFER_SIZE_EVENT`) carries the buffer
  dimensions.  The loop therefore re-queries `GetConsoleScreenBufferInfo` at a
  modest interval, which also catches the resizes Windows sends no event for at
  all -- dragging the window edge, maximising, or changing the console font.
  `Size()` falls back to opening `CONOUT$` when stdout has been redirected, so
  `winsh host cmd > out.txt` still negotiates the real window.
* **Keystrokes.** Input comes from `ReadConsoleInputW`, not from `stdin`, and
  only that way can a client honour the server's application-cursor-keys mode,
  tell Ctrl-^ from `^`, and see a keypress before the user presses Enter.  It
  depends on two things being right at once: `Open()` must classify the input
  handle as a console (a console-mode check that returns an error has a polarity
  that is easy to get backwards, and getting it backwards quietly drops the
  session into line-buffered `stdin`), and the `INPUT_RECORD` union must be
  decoded at its real offsets -- `bKeyDown` is a one-byte `BOOLEAN` followed by
  three bytes of padding, so reading it as a `WORD` slides every later field two
  bytes left and turns ordinary typing into control bytes.  Both are pinned by
  byte-exact captures in `internal/consoleapi`.

Exiting is bounded as well.  `Ctrl-^ .` starts mosh's graceful shutdown and
exits as soon as the server acknowledges it; if the last packet is lost the
client hands the terminal back after about a second instead of waiting out
mosh's ten-second retry timeout.  The other direction matters just as much:
when the remote shell exits, `mosh-server` begins its own shutdown, and the
client has to acknowledge that instruction and hang up (mosh's
`counterparty_shutdown_ack_sent` test) so that typing `exit` ends the session
rather than leaving the terminal attached to a dead one.  A one-shot command (`winsh host cmd`) ends
when `mosh-server` goes silent, since a live server always answers the
acknowledgements the client sends -- and an *interactive* session deliberately
does not, so a network hiccup cannot end your shell.

### Security notes

* **No nonce reuse.** One cipher session, driven by a single goroutine, hands
  out strictly increasing sequence numbers; the packet counter survives a
  re-dial, which is what makes roaming accepted by the server instead of
  discarded as replay.
* **Replay defence.** Received sequence numbers may not go backwards; datagrams
  with the wrong direction bit are dropped.
* **Bounded everything.** A hostile server cannot make the client allocate
  without limit: datagrams are capped at 2048 bytes, an inflated stream is
  refused at 4 MiB, retained state diffs at 32 MiB, fragment and field counts
  are capped, discarded state history is released rather than kept alive by
  parent links, only a small number of received states hold full screen
  snapshots, the screen is clamped to 512x512 cells, combining marks to 8 per
  glyph, CSI parameters and SSH channel buffers are bounded, titles to 1 KiB,
  agent replies to 1 MiB, and every SSH wire field is bounds-checked before it
  is read.  The process also sets a 256 MiB soft Go heap limit so a long-lived
  session has a fixed footprint rather than growing with its history.
* **No terminal injection from untrusted text.** OSC 0/2 titles, SSH banners,
  server errors, key comments, and other remote text have control and Unicode
  directionality characters escaped before display. OSC 52 (clipboard) is dropped
  rather than honoured — it is a known exfiltration channel.
* **Crypto failure is silent to the network.** Packets that fail
  authentication are counted and discarded; the client never tells the sender
  *why*, and never renders partial plaintext. Decryption buffers are wiped
  before they leave the packet reader.
* **SSH primitives are chosen, not accepted.**  Key exchange is
  `curve25519-sha256`; confidentiality is AES-128/256-CTR; integrity is
  HMAC-SHA-2, preferring the encrypt-then-MAC variants.  There is no CBC mode,
  no RC4, no MD5, no SHA-1 MAC, and no AES-192 even though `crypto/aes` would
  take the key: an unexpected key length is refused rather than negotiated with.
  Anything the server offers outside this list is refused with a named
  algorithm, not silently downgraded.
* **Host key verification cannot be turned off.**  An unknown key is presented
  as a `SHA256:` fingerprint and must be confirmed; a changed key is a hard
  error, `@revoked` entries always win, and negated `known_hosts` patterns are
  honoured.  The signature is checked against the exchange hash, which is what
  makes the rest of the derived key material meaningful.
* **Console safety on abnormal exit.** A `SetConsoleCtrlHandler` restores the
  console modes if the process is killed with Ctrl-C or closed, so winsh cannot
  leave your terminal in raw mode.

---

## Licensing

**winsh is free software, licensed under the GNU General Public License,
version 3 or later (GPL-3.0-or-later).**  The full text is in `LICENSE` at the
top of the tree, and the binary prints it too:

```powershell
winsh --show-licenses
```

The short version: only winsh's own source and the Go standard library
(BSD-3-Clause) are compiled into winsh.exe.  AES, the random number generator,
UDP sockets, and the console all come from Windows system DLLs loaded at run
time, and the OCB mode, the protobuf codec, the zlib use, the terminal
emulator, the SSH client, and the agent protocol are winsh's own code written
from published specifications.

Mosh, whose wire interface winsh implements, is GPLv3 software by Keith
Winstein.

---

## Known limitations

Honest list, roughly in order of how much it will bother you:

1. **The external `ssh.exe` backend is still the default.**  The native client
   (`--native-ssh`) now completes a full handshake, publickey authentication
   through Pageant, and a `mosh-server` bootstrap against OpenSSH 9.6, and its
   packet layer, negotiation, key encoding and agent protocol are pinned by
   unit tests that are written against the wire rather than against winsh's own
   helpers.  It offers fewer algorithms than OpenSSH, deliberately, so a site
   with an unusual KEX or host key type should stay on the external path.
2. **Passphrase-protected key files are not decrypted** — use Pageant or
   `ssh-agent`.  `.ppk` files are refused with the same advice.
3. **No true suspend.**  Windows has no job control, so `Ctrl-Z` detaches the
   socket and re-dials rather than stopping the process.
4. **Terminal initialisation is a fixed xterm-like string**, not a terminfo
   lookup (Windows has no terminfo database).  `--no-init` matches mosh's
   behaviour when you would rather handle that yourself.
5. **Scrollback is not emulated** — the emulator models the visible screen, as
   mosh's framebuffer does.

---

## Development

```powershell
go test ./...                                    # everything
go test ./internal/vt -run TestDiffRoundTrip -v   # the frame-diff property test
go test ./internal/transport -run Loss -v          # retransmission under dropped packets
go vet ./... && gofmt -l .                         # both should be silent
```

Every fuzz target runs its seed corpus as part of `go test ./...`. To run a
longer campaign, use `-run=^$` so only the requested fuzz target runs:

```powershell
go test ./internal/ssh -run=^$ -fuzz=FuzzVersionExchange -fuzztime=30s
go test ./internal/ssh -run=^$ -fuzz=FuzzKnownHostsParsing -fuzztime=30s
go test ./internal/bootstrap -run=^$ -fuzz=FuzzParseBootstrap -fuzztime=30s
go test ./internal/wire -run=^$ -fuzz=FuzzParse -fuzztime=30s
go test ./internal/ssp -run=^$ -fuzz=FuzzParseMessages -fuzztime=30s
go test ./internal/vt -run=^$ -fuzz=FuzzTerminalSequences -fuzztime=30s
go test ./internal/transport -run=^$ -fuzz=FuzzFragmentAndInflate -fuzztime=30s
go test ./internal/moshcrypto -run=^$ -fuzz=FuzzSessionDecrypt -fuzztime=30s
go test ./internal/keys -run=^$ -fuzz=FuzzPrivateKeyParsing -fuzztime=30s
go test ./internal/agent -run=^$ -fuzz=FuzzIdentityReplyParsing -fuzztime=30s
```

`internal/fakeserver` is a real (if minimal) mosh server speaking the same wire
protocol; `winsh --self-test` uses it so you can prove the stack works on a
machine with no network at all.
