package ssh

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsh/internal/keys"
)

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	data := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func knownHostLine(marker, patterns, algo string, blob []byte) string {
	prefix := ""
	if marker != "" {
		prefix = marker + " "
	}
	return prefix + patterns + " " + algo + " " + base64.StdEncoding.EncodeToString(blob)
}

func reviewKey(algo string, last byte) keys.PubKey {
	return keys.PubKey{Algo: algo, Blob: []byte{algo[0], last}}
}

func TestKnownHostsRevocationWinsAndFileIsClosed(t *testing.T) {
	trusted := reviewKey("ssh-ed25519", 1)
	revoked := reviewKey("ssh-ed25519", 2)
	path := writeKnownHosts(t,
		knownHostLine("", "example.test", trusted.Algo, trusted.Blob),
		knownHostLine("@revoked", "example.test", revoked.Algo, revoked.Blob),
	)

	matches, err := lookupKnownHost([]string{path}, "example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matches.check(trusted); !found || err != nil {
		t.Fatalf("trusted key: found=%v err=%v", found, err)
	}
	if found, err := matches.check(revoked); !found || !errors.Is(err, ErrHostKeyRevoked) {
		t.Fatalf("revoked key: found=%v err=%v", found, err)
	}

	// Windows refuses to remove an open file. This catches descriptor leaks
	// that would otherwise only show up after repeated connection attempts.
	if err := os.Remove(path); err != nil {
		t.Fatalf("known_hosts remained open after lookup: %v", err)
	}
}

func TestKnownHostsNegatedPatternExcludesWholeLine(t *testing.T) {
	key := reviewKey("ssh-ed25519", 3)
	path := writeKnownHosts(t,
		knownHostLine("", "*.example.test,!bad.example.test", key.Algo, key.Blob),
	)

	matches, err := lookupKnownHost([]string{path}, "bad.example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matches.check(key); found || err != nil {
		t.Fatalf("negated host matched: found=%v err=%v", found, err)
	}

	matches, err = lookupKnownHost([]string{path}, "good.example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matches.check(key); !found || err != nil {
		t.Fatalf("positive host did not match: found=%v err=%v", found, err)
	}
}

func TestKnownHostsAcceptsAnyMatchingKeyType(t *testing.T) {
	first := reviewKey("ecdsa-sha2-nistp256", 4)
	second := reviewKey("ssh-ed25519", 5)
	path := writeKnownHosts(t,
		knownHostLine("", "example.test", first.Algo, first.Blob),
		knownHostLine("", "example.test", second.Algo, second.Blob),
	)

	matches, err := lookupKnownHost([]string{path}, "example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matches.check(second); !found || err != nil {
		t.Fatalf("second host key: found=%v err=%v", found, err)
	}
}

func TestKnownHostsCertAuthorityIsNotAHostKey(t *testing.T) {
	ca := reviewKey("ssh-ed25519", 6)
	path := writeKnownHosts(t,
		knownHostLine("@cert-authority", "*.example.test", ca.Algo, ca.Blob),
	)

	matches, err := lookupKnownHost([]string{path}, "host.example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	found, err := matches.check(ca)
	if !found || !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("certificate authority verdict: found=%v err=%v", found, err)
	}
}

func TestKnownHostsNonstandardPortIsScoped(t *testing.T) {
	if got := knownHostName("[example.test]:2222", 2222); got != "[example.test]:2222" {
		t.Fatalf("port-qualified host was wrapped again: %q", got)
	}
	key := reviewKey("ssh-ed25519", 7)
	plain := writeKnownHosts(t,
		knownHostLine("", "example.test", key.Algo, key.Blob),
	)
	matches, err := lookupKnownHost([]string{plain}, "example.test", 2222)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matches.check(key); found || err != nil {
		t.Fatalf("plain host entry matched a nonstandard port: found=%v err=%v", found, err)
	}

	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := AppendKnownHost([]string{path}, "example.test", 2222, key); err != nil {
		t.Fatal(err)
	}
	matches, err = lookupKnownHost([]string{path}, "example.test", 2222)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matches.check(key); !found || err != nil {
		t.Fatalf("nonstandard-port key: found=%v err=%v", found, err)
	}
}

func TestKnownHostsUnknownMarkerIsIgnored(t *testing.T) {
	key := reviewKey("ssh-ed25519", 8)
	path := writeKnownHosts(t,
		knownHostLine("@future-marker", "example.test", key.Algo, key.Blob),
	)
	matches, err := lookupKnownHost([]string{path}, "example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := matches.check(key); found || err != nil {
		t.Fatalf("unknown marker was trusted: found=%v err=%v", found, err)
	}
}
