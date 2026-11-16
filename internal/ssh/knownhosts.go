package ssh

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"winsh/internal/keys"
)

// known_hosts parsing and matching.
//
// Both the plain and the hashed ($HASHED$) formats OpenSSH writes are
// understood. Hashed entries store HMAC-SHA1(salt, hostname); the SHA-1 here
// is used only as an obfuscation of the hostname, never as a security check,
// so it is not a weakness in the way SHA-1 host-key signatures would be.

type knownEntry struct {
	marker   string
	patterns []string
	algo     string
	blob     []byte
	hashed   bool
	salt     []byte
	digest   []byte
}

type knownHostMatches struct {
	trusted     []keys.PubKey
	revoked     []keys.PubKey
	authorities []keys.PubKey
}

// lookupKnownHost returns every entry that applies to host:port. The caller
// must classify the result; in particular, a matching @revoked entry always
// wins over a matching trusted entry.
func lookupKnownHost(files []string, host string, port int) (knownHostMatches, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var matches knownHostMatches
	for _, path := range files {
		entries, err := readKnownHostFile(path)
		if err != nil {
			return knownHostMatches{}, err
		}
		for _, entry := range entries {
			if !entry.matches(host, port) {
				continue
			}
			k := keys.PubKey{Algo: entry.algo, Blob: entry.blob, Comment: host}
			switch entry.marker {
			case "@revoked":
				matches.revoked = append(matches.revoked, k)
			case "@cert-authority":
				matches.authorities = append(matches.authorities, k)
			default:
				matches.trusted = append(matches.trusted, k)
			}
		}
	}
	return matches, nil
}

func readKnownHostFile(path string) ([]knownEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // missing known_hosts is normal on first use
		}
		return nil, fmt.Errorf("ssh: read %s: %w", path, err)
	}
	defer f.Close()

	var out []knownEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if entry, ok := parseKnownHostLine(sc.Text()); ok {
			out = append(out, entry)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ssh: read %s: %w", path, err)
	}
	return out, nil
}

func parseKnownHostLine(line string) (knownEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return knownEntry{}, false
	}
	fields := strings.Fields(line)
	marker := ""
	markers := 0
	for len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		marker = fields[0]
		markers++
		fields = fields[1:]
	}
	if markers > 1 {
		return knownEntry{}, false
	}
	switch marker {
	case "", "@revoked", "@cert-authority":
	default:
		// Unknown markers must not turn into ordinary trusted keys.
		return knownEntry{}, false
	}
	if len(fields) < 3 {
		return knownEntry{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(blob) == 0 {
		return knownEntry{}, false
	}
	e := knownEntry{
		marker:   marker,
		patterns: strings.Split(fields[0], ","),
		algo:     fields[1],
		blob:     blob,
	}
	if len(e.patterns) == 1 && strings.HasPrefix(e.patterns[0], "|1|") {
		parts := strings.Split(e.patterns[0], "|")
		if len(parts) != 4 {
			return knownEntry{}, false
		}
		salt, err1 := base64.StdEncoding.DecodeString(parts[2])
		digest, err2 := base64.StdEncoding.DecodeString(parts[3])
		if err1 != nil || err2 != nil {
			return knownEntry{}, false
		}
		e.hashed = true
		e.salt = salt
		e.digest = digest
	}
	return e, true
}

func (e knownEntry) matches(host string, port int) bool {
	candidates := []string{knownHostName(host, port)}
	for _, cand := range candidates {
		if e.hashed {
			if e.hashMatches(cand) {
				return true
			}
			continue
		}
		if matchesPatternList(e.patterns, cand) {
			return true
		}
	}
	return false
}

func (e knownEntry) hashMatches(host string) bool {
	m := hmac.New(sha1.New, e.salt)
	m.Write([]byte(host))
	return hmac.Equal(m.Sum(nil), e.digest)
}

// matchesPatternList implements OpenSSH's line-level pattern semantics. A
// negated pattern excludes the whole line even when a positive pattern also
// matches.
func matchesPatternList(patterns []string, host string) bool {
	host = strings.ToLower(host)
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "!") {
			if glob(strings.ToLower(pattern[1:]), host) {
				return false
			}
		}
	}
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "!") {
			continue
		}
		if glob(strings.ToLower(pattern), host) {
			return true
		}
	}
	return false
}

func glob(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	pi, si := 0, 0
	star, mark := -1, 0
	pl, sl := len(pattern), len(s)
	for si < sl {
		if pi < pl && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			pi++
			si++
		} else if pi < pl && pattern[pi] == '*' {
			star = pi
			mark = si
			pi++
		} else if star >= 0 {
			pi = star + 1
			mark++
			si = mark
		} else {
			return false
		}
	}
	for pi < pl && pattern[pi] == '*' {
		pi++
	}
	return pi == pl
}

func samePublicKey(a, b keys.PubKey) bool {
	return a.Algo == b.Algo && bytes.Equal(a.Blob, b.Blob)
}

// check makes the trust decision for an offered host key. found reports
// whether known_hosts contained an entry relevant to this host; when found is
// false, the caller may offer trust-on-first-use.
func (m knownHostMatches) check(pub keys.PubKey) (found bool, err error) {
	for _, k := range m.revoked {
		if samePublicKey(k, pub) {
			return true, fmt.Errorf("%w: %s %s", ErrHostKeyRevoked, pub.Algo, pub.Fingerprint())
		}
	}
	for _, k := range m.trusted {
		if samePublicKey(k, pub) {
			return true, nil
		}
	}
	if len(m.trusted) > 0 {
		k := m.trusted[0]
		return true, fmt.Errorf("%w\n  expected %s %s\n  got      %s %s",
			ErrHostKeyChanged, k.Algo, k.Fingerprint(), pub.Algo, pub.Fingerprint())
	}
	if len(m.authorities) > 0 {
		return true, fmt.Errorf("%w: host matches an @cert-authority entry, but winsh does not verify SSH host certificates",
			ErrHostKeyUnknown)
	}
	return false, nil
}

func knownHostName(host string, port int) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
		return host
	}
	if port != 0 && port != 22 {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return host
}

// HostKeyFingerprints lists what known_hosts holds for a host, so the user can
// compare it with what the server presents.
func HostKeyFingerprints(files []string, host string, port int) []string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var out []string
	for _, path := range files {
		entries, err := readKnownHostFile(path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.matches(host, port) {
				continue
			}
			k := keys.PubKey{Algo: entry.algo, Blob: entry.blob}
			marker := ""
			if entry.marker != "" {
				marker = entry.marker + " "
			}
			out = append(out, fmt.Sprintf("%s%s %s", marker, entry.algo, k.Fingerprint()))
		}
	}
	return out
}

// AppendKnownHost stores a host key, implementing trust-on-first-use. The
// entry is written in the same plain format ssh-keygen and ssh use.
func AppendKnownHost(files []string, host string, port int, k keys.PubKey) error {
	if len(files) == 0 {
		return errors.New("ssh: no known_hosts path configured")
	}
	if k.Algo == "" || len(k.Blob) == 0 {
		return errors.New("ssh: refusing to store an empty host key")
	}
	path := files[0]
	if dir := dirName(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("ssh: %s: %w", dir, err)
		}
	}
	name := knownHostName(host, port)
	line := fmt.Sprintf("%s %s %s\n", name, k.Algo, base64.StdEncoding.EncodeToString(k.Blob))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("ssh: %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("ssh: %s: %w", path, err)
	}
	return nil
}

func dirName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[:i]
		}
	}
	return ""
}
