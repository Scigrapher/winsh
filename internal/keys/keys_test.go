package keys_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"winsh/internal/agent"
	"winsh/internal/keys"
)

// generateKey writes a fresh unencrypted key of the given type with ssh-keygen
// when it is available, which lets the tests exercise the parser against real
// OpenSSH key files rather than hand-made ones.
func generateKey(t *testing.T, dir, name, keyType string) string {
	t.Helper()
	bin := filepath.Join(os.Getenv("WINDIR"), "System32", "OpenSSH", "ssh-keygen.exe")
	if _, err := os.Stat(bin); err != nil {
		if bin, err = exec.LookPath("ssh-keygen"); err != nil {
			t.Skip("ssh-keygen is not available")
		}
	}
	path := filepath.Join(dir, name)
	cmd := exec.Command(bin, "-t", keyType, "-N", "", "-C", "winsh-test", "-f", path)
	cmd.Stdin = strings.NewReader("\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen could not generate a %s key: %v (%s)", keyType, err, out)
	}
	return path
}

func TestLoadOpenSSHKeysAndSignVerify(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, type_, algo string
	}{
		{"id_ed25519", "ed25519", "ssh-ed25519"},
		{"id_rsa", "rsa", "ssh-rsa"},
		{"id_ecdsa", "ecdsa", "ecdsa-sha2-nistp256"},
	} {
		path := generateKey(t, dir, tc.name, tc.type_)
		signers, notes := keys.LoadFiles([]string{path})
		if len(signers) != 1 {
			t.Fatalf("%s: expected one signer, got %d (%v)", tc.name, len(signers), notes)
		}
		s := signers[0]
		pub := s.Pub()
		if pub.Algo != tc.algo {
			t.Errorf("%s: algo = %s, want %s", tc.name, pub.Algo, tc.algo)
		}
		if !strings.HasPrefix(pub.Fingerprint(), "SHA256:") {
			t.Errorf("%s: odd fingerprint %q", tc.name, pub.Fingerprint())
		}
		msg := []byte("the bytes being signed by the SSH userauth exchange")
		sig, err := s.Sign("", msg)
		if err != nil {
			t.Fatalf("%s: Sign: %v", tc.name, err)
		}
		// RSA keys offer rsa-sha2-256 first; verify with the algorithm the
		// signature actually claims.
		if err := keys.VerifyHostKey(pub, msg, sig, false); err != nil {
			if strings.Contains(err.Error(), "SHA-1") {
				t.Logf("%s: signature uses SHA-1, refusing by default as intended", tc.name)
				continue
			}
			t.Fatalf("%s: VerifyHostKey: %v", tc.name, err)
		}
		// Every advertised algorithm has to be produced when it is asked
		// for, and the signature must name the one requested. Asking for
		// rsa-sha2-512 and quietly getting rsa-sha2-256 back makes OpenSSH
		// refuse a perfectly good key with no explanation at all.
		for _, algo := range s.AllowedAlgos() {
			got, err := s.Sign(algo, msg)
			if err != nil {
				t.Errorf("%s: Sign(%s): %v", tc.name, algo, err)
				continue
			}
			if named := keys.SignatureAlgo(got); named != algo {
				t.Errorf("%s: Sign(%s) returned a %s signature", tc.name, algo, named)
				continue
			}
			if err := keys.VerifyHostKey(pub, msg, got, algo == "ssh-rsa"); err != nil {
				t.Errorf("%s: VerifyHostKey for %s: %v", tc.name, algo, err)
			}
		}

		// Tampering must be detected.
		bad := append([]byte(nil), msg...)
		bad[0] ^= 0x01
		if err := keys.VerifyHostKey(pub, bad, sig, false); err == nil {
			t.Errorf("%s: signature verified with a altered message", tc.name)
		}
	}
}

func TestEncryptedKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_enc")
	// A passphrase-protected OpenSSH key: winsh must refuse it rather than
	// prompt for a passphrase, and say why.
	bin := filepath.Join(os.Getenv("WINDIR"), "System32", "OpenSSH", "ssh-keygen.exe")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("ssh-keygen is not available")
	}
	cmd := exec.Command(bin, "-t", "ed25519", "-N", "secret", "-f", path)
	cmd.Stdin = strings.NewReader("\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not generate an encrypted key: %v (%s)", err, out)
	}
	_, notes := keys.LoadFiles([]string{path})
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, " "), "passphrase") {
		t.Fatalf("expected a passphrase refusal note, got %v", notes)
	}
}

func TestPPKIsRejectedWithGuidance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.ppk")
	os.WriteFile(path, []byte("PPK-VERSION\nPuTTY Private Key File\n"), 0o600)
	_, notes := keys.LoadFiles([]string{path})
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, " "), "Pageant") {
		t.Fatalf("expected guidance about Pageant, got %v", notes)
	}
}

func TestBlobParsingRejectsGarbage(t *testing.T) {
	if _, err := keys.ParsePublicBlob([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Fatalf("malformed blob accepted")
	}
	if _, err := keys.ParsePublicBlob(append([]byte{0, 0, 0, 9}, []byte("ssh-rsa")...)); err == nil {
		t.Fatalf("truncated rsa blob accepted")
	}
	pub := keys.PubKey{Algo: "ssh-ed25519", Blob: bytes.Repeat([]byte{1}, 40)}
	if err := keys.VerifyHostKey(pub, []byte("x"), []byte("garbage"), false); err == nil {
		t.Fatalf("garbage signature accepted")
	}
}

// TestAgainstLiveAgent exercises the real agent path when Pageant or
// ssh-agent is running, which is the configuration the requirement asks for.
func TestAgainstLiveAgent(t *testing.T) {
	cl, tried, err := agent.ConnectFirst(nil)
	if err != nil {
		t.Skipf("no SSH agent available (%v); tried %d endpoints", err, len(tried))
	}
	defer cl.Close()
	ids, err := cl.Identities()
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	t.Logf("agent %s has %d key(s)", cl.Name(), len(ids))
	signers, err := keys.FromAgent(cl)
	if err != nil {
		t.Fatalf("FromAgent: %v", err)
	}
	for _, s := range signers {
		t.Logf("  %s %s (%s)", s.Pub().Algo, s.Pub().Fingerprint(), s.Source())
	}
}
