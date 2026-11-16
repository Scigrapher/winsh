package keys

import (
	"encoding/base64"
	"testing"
)

func FuzzPublicKeyParsing(f *testing.F) {
	blob := buildEd25519Blob(make([]byte, 32))
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " fuzz"
	f.Add(line, blob)
	f.Add("ssh-rsa AAAA", []byte{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'})
	f.Add("", []byte{})
	f.Add("not-a-key", []byte{0xff})

	f.Fuzz(func(t *testing.T, text string, blob []byte) {
		if len(text) > 32*1024 || len(blob) > 32*1024 {
			return
		}
		if key, err := ParsePublicLine(text); err == nil {
			_ = key.Fingerprint()
		}
		if key, err := ParsePublicBlob(blob); err == nil {
			_ = key.Fingerprint()
		}
	})
}

func FuzzPrivateKeyParsing(f *testing.F) {
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("PPK-VERSION:2\r\n"))
	f.Add([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		_, _ = parsePrivateKey(data, "fuzz-key")
	})
}
