package cli

import (
	"fmt"
	"strings"
)

// Usage returns the help text.  mosh's options are listed first, in mosh's
// order, because the point is that muscle memory keeps working.
func Usage(prog string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: %s [options] [--] [user@]host [command...]\n", prog)
	b.WriteString(`        --client=PATH        mosh client on local machine
                                (default: "mosh-client", accepted for compatibility)
        --server=COMMAND     mosh server on remote machine
                                (default: "mosh-server")

        --predict=adaptive      local echo for slower links [default]
-a      --predict=always        use local echo even on fast links
-n      --predict=never         never use local echo
        --predict=experimental  aggressively echo even when incorrect
-o      --predict-overwrite     prediction overwrites instead of inserting

        --family=inet        use IPv4 only
        --family=inet6       use IPv6 only
        --family=auto        autodetect network type for single-family hosts only
        --family=all         try all network types
        --family=prefer-inet use all network types, but try IPv4 first [default]
        --family=prefer-inet6 use all network types, but try IPv6 first
-4                         same as --family=inet
-6                         same as --family=inet6

-p PORT[:PORT2]
        --port=PORT[:PORT2]  server-side UDP port or range
        --ssh=COMMAND        ssh command to run when setting up session
                                (example: "ssh -p 2222"); implies --external-ssh
        --ssh-option=OPT     extra option passed to ssh (external mode)
        --ssh-port=PORT      server-side SSH port
        --ssh-proxy-command=COMMAND  ProxyCommand to use
        --no-ssh-pty         do not allocate a pseudo tty on ssh connection
        --no-init            do not send terminal initialization string
        --local              run mosh-server locally without using ssh
        --bind-server={ssh|any|IP}  ask the server to reply from an IP address
                                     (default: "ssh")
        --experimental-remote-ip=(local|remote|proxy)  how to discover the
                                     remote IP address (default: "proxy")

        --key=KEY            connect with a known session key (22 base64 chars),
                                     skipping the SSH bootstrap: "winsh --key=K host port"
        --shutdown-after-idle=SECS  exit after this much user inactivity
        --timeout=SECS       exit if the server is silent this long
        --connect-timeout=SECS       give up connecting after this long (default 15)
-e      --echo-cancel        enable predictive echo handling (the default)

        --native-ssh         force winsh's built-in SSH client (default; uses
                                     Pageant and ~/.ssh keys directly)
        --external-ssh       force an external ssh(1) for the bootstrap
        -v, --verbose        per-packet and bootstrap diagnostics on stderr
        --dump-screen        print the final screen text to stdout on exit
        --no-escape-key      turn the escape key off entirely (see ESCAPE KEY)

ESCAPE KEY

  Ctrl-^ -- that is Ctrl+Shift+6 -- introduces the session commands.  Because it
  is a control character it works anywhere, mid-line included; you do not have
  to press Enter first.

        Ctrl-^ .            quit (graceful shutdown handshake)
        Ctrl-^ Ctrl-Z       detach: the server keeps running; press Enter to
                            reattach over a fresh UDP port
        Ctrl-^ ^            type a literal Ctrl-^
        Ctrl-^ <anything>   send both bytes to the server untouched
        Ctrl-L              repaint the screen

  If your terminal swallows Ctrl+Shift+6, choose another escape key with
  MOSH_ESCAPE_KEY=<one character> (mosh's own rules: values 1..127, an empty
  value disables it, and Ctrl-C, Ctrl-D, Ctrl-L, CR and LF are refused because
  you need them to leave or to type a newline), or pass --no-escape-key.
  A printable escape key must follow a newline, again exactly as in mosh, so
  that typing it in ordinary input stays possible.

        --help               this message
        --version            version and copyright information
        --show-licenses      license and attribution report
        --diagnostics        report which Windows libraries are in use
        --list-keys          list keys available from Pageant/ssh-agent and ~/.ssh

winsh is a Windows-native, single-binary, memory-safe mosh client.  It speaks
the mosh 1.4 protocol (SSP over UDP with AES-128-OCB) and needs no installation.

Please report bugs to the winsh project.  Mosh itself is https://mosh.org.
`)
	return b.String()
}

// VersionBanner is printed by --version.
func VersionBanner(prog string) string {
	return fmt.Sprintf(`%s (%s) %s
Copyright (C) 2026 winsh contributors.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program.  If not, see <https://www.gnu.org/licenses/>.

Run "%s --show-licenses" for the license text, which also carries the Go
standard library's BSD-3-Clause notice.

Mosh is GPLv3 software by Keith Winstein; winsh implements its published wire
interface.`, prog, "Windows-native mosh client", Version, prog)
}
