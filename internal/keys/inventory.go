package keys

// Key inventory, backing "winsh --list-keys".  This reports what the client
// would be able to authenticate with, from the same two sources the real
// connection uses: a running agent (Pageant first, then ssh-agent) and the
// conventional files under ~/.ssh.  It is deliberately read-only: it never
// signs, never prompts, and never decrypts anything.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"winsh/internal/agent"
	"winsh/internal/textsafe"
)

// KeyEntry is one candidate signing key.
type KeyEntry struct {
	// Source is where the key came from, for instance "agent:Pageant" or
	// "file:C:\Users\me\.ssh\id_ed25519".
	Source string
	// Algo is the SSH key type, or "" when it could not be determined.
	Algo string
	// Fingerprint is the SHA-256 fingerprint, or "" when unknown.
	Fingerprint string
	// Comment is the agent comment, or the file name for a key on disk.
	Comment string
	// SignatureAlgos lists the algorithms winsh will offer for this key.
	SignatureAlgos []string
	// Usable is false when the key is visible but cannot sign, such as a
	// passphrase-protected file, a PuTTY .ppk, or a public half with no
	// private key beside it.
	Usable bool
	// Note explains a non-obvious state.
	Note string
}

// AgentProbe records one agent endpoint that was attempted, so the report can
// say that Pageant simply is not running instead of staying silent about it.
type AgentProbe struct {
	Name    string
	Reached bool
	Keys    int
	Err     string
}

// Inventory lists every key winsh could authenticate with.  home is the value
// used to find ~/.ssh; pass "" to use os.UserHomeDir.  The returned probes
// describe the agent endpoints that were tried, and notes carry anything the
// user should know about what was skipped.
func Inventory(env map[string]string, home string) (entries []KeyEntry, probes []AgentProbe, notes []string) {
	seen := map[string]bool{}
	add := func(e KeyEntry) {
		k := e.Source + "|" + e.Fingerprint
		if seen[k] {
			return
		}
		seen[k] = true
		entries = append(entries, e)
	}

	for _, cand := range agent.Candidates(env) {
		probe := AgentProbe{Name: cand.Name}
		cl, err := agent.Dial(cand)
		if err != nil {
			probe.Err = err.Error()
			probes = append(probes, probe)
			continue
		}
		ids, err := cl.Identities()
		if err != nil {
			if errors.Is(err, agent.ErrNoKeys) {
				// The agent answered properly; it just has nothing loaded.
				// Say so plainly, because the alternative reading -- a broken
				// agent -- wastes an afternoon of pipe forensics.
				probe.Reached = true
				probe.Keys = 0
				probe.Err = "answered, but holds no keys"
				notes = append(notes, fmt.Sprintf(
					"agent %s is running and answered correctly, but holds no keys; load one first "+
						"(PuTTY's Pageant reads .ppk files and rejects OpenSSH-format private keys on older versions)",
					cand.Name))
				cl.Close()
				probes = append(probes, probe)
				continue
			}
			// Report a refusal as its own outcome. Claiming "holds no
			// keys" when the agent actually rejected the request sends
			// people to tell their agent to load a key it already has.
			probe.Reached = true
			why := err.Error()
			// The agent package already prefixes its errors with
			// "agent <name>: ", so adding it again here is how the report
			// came to read "agent Pageant: agent Pageant: ...".
			if pfx := "agent " + cand.Name + ": "; strings.HasPrefix(why, pfx) {
				why = why[len(pfx):]
			}
			probe.Err = why
			if errors.Is(err, agent.ErrRefused) {
				notes = append(notes, fmt.Sprintf(
					"agent %s refused the identity request; it may be holding no keys, "+
						"or it may not recognise this client", cand.Name))
			} else {
				notes = append(notes, fmt.Sprintf("agent %s: %v", cand.Name, why))
			}
			cl.Close()
			probes = append(probes, probe)
			continue
		}
		probe.Reached = true
		probe.Keys = len(ids)
		for _, id := range ids {
			pub, err := ParsePublicBlob(id.Blob)
			if err != nil {
				notes = append(notes, fmt.Sprintf("agent %s: skipping %s: %v", cand.Name, safeComment(id.Comment), err))
				continue
			}
			add(KeyEntry{
				Source:         "agent:" + cl.Name(),
				Algo:           pub.Algo,
				Fingerprint:    pub.Fingerprint(),
				Comment:        safeComment(id.Comment),
				SignatureAlgos: algosFor(pub.Algo),
				Usable:         true,
			})
		}
		// The inventory does not need the connection, and unlike a live
		// session it must not leak a handle.
		cl.Close()
		probes = append(probes, probe)
	}

	if home == "" {
		home, _ = os.UserHomeDir()
	}
	paths := DefaultPaths(home)
	if env != nil {
		if v := env["SSH_IDENTITY"]; v != "" {
			paths = append(paths, v)
		}
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			// No private key: report the public half alone, if it exists, so
			// that a stray identity.pub is not mistaken for an available key.
			if pub, ok := readPublicKeyFile(p + ".pub"); ok {
				add(KeyEntry{
					Source:      "file:" + p,
					Algo:        pub.Algo,
					Fingerprint: pub.Fingerprint(),
					Comment:     filepath.Base(p) + ".pub",
					Note:        "public half only; no private key file to go with it",
				})
			}
			continue
		}
		signer, err := parsePrivateKey(data, p)
		if err != nil {
			e := KeyEntry{Source: "file:" + p, Comment: filepath.Base(p), Note: err.Error()}
			if pub, ok := readPublicKeyFile(p + ".pub"); ok {
				e.Algo = pub.Algo
				e.Fingerprint = pub.Fingerprint()
			}
			add(e)
			continue
		}
		pub := signer.Pub()
		add(KeyEntry{
			Source:         signer.Source(),
			Algo:           pub.Algo,
			Fingerprint:    pub.Fingerprint(),
			Comment:        safeComment(pub.Comment),
			SignatureAlgos: signer.AllowedAlgos(),
			Usable:         true,
		})
	}
	return entries, probes, notes
}

// readPublicKeyFile parses one OpenSSH ".pub" file.
func readPublicKeyFile(path string) (PubKey, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PubKey{}, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, err := ParsePublicLine(line); err == nil {
			return k, true
		}
	}
	return PubKey{}, false
}

// ParsePublicLine parses a single "algorithm base64 comment" line of the form
// used by identity.pub and authorized_keys.  Certificate and security-key
// forms are accepted only if they carry a blob winsh can actually verify.
func ParsePublicLine(line string) (PubKey, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return PubKey{}, fmt.Errorf("keys: not a public key line")
	}
	// An options field (from(0,1) ... ssh-rsa AAAA) would land in fields[0];
	// real algorithm names always contain a hyphen and never a parenthesis.
	if strings.ContainsAny(fields[0], "()=") || !strings.Contains(fields[0], "-") {
		return PubKey{}, fmt.Errorf("keys: public key line starts with options, not an algorithm")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return PubKey{}, fmt.Errorf("keys: bad base64 in public key: %v", err)
	}
	k, err := ParsePublicBlob(blob)
	if err != nil {
		return PubKey{}, err
	}
	if len(fields) > 2 {
		k.Comment = safeComment(strings.Join(fields[2:], " "))
	}
	return k, nil
}

// safeComment escapes control and directionality characters from text that
// originated outside winsh (an agent comment, a file name chosen by someone
// else). The report is printed straight to the console, so untrusted text must
// not be able to redraw or spoof the terminal.
func safeComment(s string) string {
	return textsafe.Line(s, 128)
}

// FormatInventory renders the report.  It is a pure function of its inputs so
// that it can be tested without an agent or a home directory.
func FormatInventory(entries []KeyEntry, probes []AgentProbe, notes []string) string {
	var b strings.Builder
	b.WriteString("winsh key inventory\n")
	b.WriteString("===================\n\n")

	b.WriteString("Agents\n")
	if len(probes) == 0 {
		b.WriteString("  (none configured)\n")
	}
	for _, p := range probes {
		label := p.Name
		if len(label) > agentNameWidth {
			label = label[:agentNameWidth-1] + "..."
		}
		switch {
		case !p.Reached:
			fmt.Fprintf(&b, "  %-*s not available (%s)\n", agentNameWidth, label, p.Err)
		case p.Keys == 0:
			fmt.Fprintf(&b, "  %-*s reachable, holds no keys\n", agentNameWidth, label)
		default:
			fmt.Fprintf(&b, "  %-*s reachable, %d key(s)\n", agentNameWidth, label, p.Keys)
		}
	}

	b.WriteString("\nKeys winsh can sign with\n")
	usable := 0
	for _, e := range entries {
		if !e.Usable {
			continue
		}
		usable++
		fmt.Fprintf(&b, "  %-18s %s\n", e.Algo, e.Fingerprint)
		fmt.Fprintf(&b, "    source:  %s\n", e.Source)
		if e.Comment != "" {
			fmt.Fprintf(&b, "    comment: %s\n", e.Comment)
		}
		fmt.Fprintf(&b, "    offers:  %s\n", strings.Join(e.SignatureAlgos, ", "))
	}
	if usable == 0 {
		b.WriteString("  (none)\n")
	}

	if blocked := entriesWithoutUsable(entries); len(blocked) > 0 {
		b.WriteString("\nKeys found but unusable\n")
		for _, e := range blocked {
			algo := e.Algo
			if algo == "" {
				algo = "unknown"
			}
			fp := e.Fingerprint
			if fp == "" {
				fp = "(unreadable)"
			}
			fmt.Fprintf(&b, "  %-18s %s\n", algo, fp)
			fmt.Fprintf(&b, "    source:  %s\n", e.Source)
			fmt.Fprintf(&b, "    reason:  %s\n", e.Note)
		}
	}

	for _, n := range notes {
		fmt.Fprintf(&b, "\nnote: %s\n", n)
	}
	if usable > 0 {
		b.WriteString("\nPassphrase-protected keys and PuTTY .ppk files are never decrypted by winsh.\n")
		b.WriteString("Load them into Pageant instead, which keeps the key in memory and signs on\n")
		b.WriteString("request.  winsh finds Pageant by enumerating \\\\.\\pipe\\pageant.*, because\n")
		b.WriteString("since PuTTY 0.76 its pipe name is derived from the logon SID and cannot\n")
		b.WriteString("be guessed, and it verifies that the pipe is owned by this user first.\n")
	}
	return b.String()
}

// agentNameWidth pads the agent column in the report.
const agentNameWidth = 34

func entriesWithoutUsable(entries []KeyEntry) []KeyEntry {
	var out []KeyEntry
	for _, e := range entries {
		if !e.Usable {
			out = append(out, e)
		}
	}
	return out
}
