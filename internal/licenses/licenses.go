// Package licenses records the license of everything that ends up in the winsh
// binary, and renders it for "winsh --show-licenses".
//
// Compiled into winsh.exe are winsh's own source, licensed under the GNU
// General Public License version 3 or later, and the Go standard library
// (BSD-3-Clause).  The report also carries the mosh protocol entry, because
// the protocol winsh speaks is itself GPLv3 software.
package licenses

import (
	_ "embed"
	"fmt"
	"strings"
)

// Component is one entry in the license report.
type Component struct {
	Name    string
	License string
	Source  string
	// Redistributed is true when code from this component is compiled into
	// winsh.exe.
	Redistributed bool
	// Copyleft flags licenses that could impose reciprocal licensing.
	Copyleft bool
	Notes    string
	Text     string
}

// Components is the full inventory.  Order matters: it is the order
// --show-licenses prints.
var Components = []Component{
	{
		Name:          "winsh",
		License:       "GPL-3.0-or-later",
		Source:        "this program",
		Redistributed: true,
		Copyleft:      true,
		Notes: "All winsh source, including the OCB, SSP, terminal-emulator, SSH, and agent " +
			"implementations.  You may copy, distribute and modify it under the terms of the " +
			"GNU General Public License as published by the Free Software Foundation, either " +
			"version 3 of the License, or (at your option) any later version.  Distributions " +
			"must carry the license text, which --show-licenses prints in full.",
		Text: GPLv3,
	},
	{
		Name:          "Go standard library and runtime",
		License:       "BSD-3-Clause",
		Source:        "Go toolchain (crypto/aes, compress/zlib, net, syscall, ...)",
		Redistributed: true,
		Notes: "winsh links only packages from the Go standard library; no third-party modules are " +
			"used. The Go runtime and standard library are BSD-3-Clause; the Go toolchain itself is " +
			"not redistributed in the binary.",
		Text: GoBSD,
	},
	{
		Name:          "mosh protocol",
		License:       "GPLv3",
		Source:        "mosh 1.4.0 wire interface",
		Redistributed: false,
		Copyleft:      true,
		Notes: "mosh is GPLv3 software by Keith Winstein. The SSP framing, Instruction " +
			"messages, cipher suite, and the graceful-shutdown handshake (including the " +
			"2^64-1 sentinel that marks a side as shutting down) describe that protocol, " +
			"and the mosh-server on the remote host is subject to it.",
	},
}

// GPLv3 is the license winsh itself is distributed under.  It is compiled in
// rather than read from disk because winsh.exe ships standalone: --show-licenses
// has to be able to print the terms from the binary alone.  The test in
// licenses_test.go keeps this copy textually identical to the LICENSE file at
// the top of the source tree, regardless of checkout line endings.
//
//go:embed gpl-3.0.txt
var GPLv3 string

// GoBSD is the licence of the Go standard library, which is statically linked
// into winsh.exe.
const GoBSD = `Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`

// Summary is the one-paragraph answer to "what license do I have to deal with".
func Summary() string {
	return "winsh is free software licensed under the GNU General Public License, version 3 " +
		"or later (GPL-3.0-or-later): you may redistribute it and modify it, provided " +
		"distributions carry the same license and the license text. The only other code " +
		"compiled into winsh.exe is the Go standard library (BSD-3-Clause), which is " +
		"statically linked and compatible with GPLv3. The mosh protocol, whose wire " +
		"interface winsh implements, is GPLv3."
}

// Report renders the whole inventory for --show-licenses.
func Report() string {
	var b strings.Builder
	b.WriteString("winsh license report\n")
	b.WriteString(strings.Repeat("=", 60) + "\n\n")
	b.WriteString(Summary() + "\n\n")
	for i, c := range Components {
		fmt.Fprintf(&b, "%d. %s\n", i+1, c.Name)
		fmt.Fprintf(&b, "   License:       %s\n", c.License)
		fmt.Fprintf(&b, "   Source:        %s\n", c.Source)
		linked := "no"
		if c.Redistributed {
			linked = "yes, compiled into winsh.exe"
		}
		fmt.Fprintf(&b, "   In the binary: %s\n", linked)
		if c.Copyleft {
			b.WriteString("   Copyleft:      yes (see notes)\n")
		}
		if c.Notes != "" {
			fmt.Fprintf(&b, "   Notes:         %s\n", wrap(c.Notes, 78, 18))
		}
		if c.Text != "" {
			b.WriteString("\n")
			b.WriteString(indent(c.Text, "     "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}

func wrap(s string, width, pad int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	// The caller has already printed the label, which occupies exactly pad
	// columns, so the first line must not be indented again; only the
	// continuations get the padding.
	pos := pad
	for i, w := range words {
		if i > 0 {
			if pos+len(w)+1 > width {
				b.WriteString("\n")
				b.WriteString(strings.Repeat(" ", pad))
				pos = pad
			} else {
				b.WriteString(" ")
				pos++
			}
		}
		b.WriteString(w)
		pos += len(w)
	}
	return b.String()
}
