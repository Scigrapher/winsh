package ssh

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func FuzzKnownHostsParsing(f *testing.F) {
	key := base64.StdEncoding.EncodeToString([]byte("fuzz-key"))
	f.Add("example.test ssh-ed25519 "+key, "example.test", "*.test")
	f.Add("@revoked example.test ssh-ed25519 "+key, "example.test", "*.test,!bad.test")
	f.Add("@cert-authority *.test ssh-ed25519 "+key, "host.test", "*")
	f.Add("|1|c2FsdA==|ZGlnZXN0 ssh-ed25519 "+key, "example.test", "*")

	f.Fuzz(func(t *testing.T, line, host, patterns string) {
		if len(line) > 8192 || len(host) > 8192 || len(patterns) > 8192 {
			return
		}
		entry, ok := parseKnownHostLine(line)
		if ok {
			_ = entry.matches(strings.ToLower(host), 22)
			_ = entry.matches(strings.ToLower(host), 2222)
		}
		_ = matchesPatternList(strings.Split(patterns, ","), host)
		_ = knownHostName(host, 22)
		_ = knownHostName(host, 2222)
	})
}

func FuzzReadPlaintextSSHPacket(f *testing.F) {
	for _, payload := range [][]byte{
		{msgIgnore},
		{msgDisconnect, 0, 0, 0, 2},
		{msgKexInit},
		append([]byte{msgDebug}, bytes.Repeat([]byte{'x'}, 64)...),
	} {
		packet, err := framePacket(payload, 8, 0)
		if err == nil {
			f.Add(packet)
		}
	}
	f.Add([]byte{0, 0, 0, 5, 4, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		c := &Client{
			conn: &memConn{r: bytes.NewReader(nil), w: &bytes.Buffer{}},
			r:    bufio.NewReader(bytes.NewReader(data)),
		}
		_, _ = c.readPacket()
	})
}

func FuzzKexInitFieldParsing(f *testing.F) {
	var seed builder
	seed.raw(make([]byte, 16))
	seed.strs(kexAlgorithms)
	seed.strs(hostKeyAlgorithms)
	seed.strs(cipherAlgorithms)
	seed.strs(cipherAlgorithms)
	seed.strs(macAlgorithms)
	seed.strs(macAlgorithms)
	seed.strs([]string{"none"})
	seed.strs([]string{"none"})
	seed.strs(nil)
	seed.strs(nil)
	seed.boolv(false)
	seed.uint32(0)
	f.Add(seed.b)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		m := &msg{b: data}
		_, _ = m.fixed(16)
		_, _ = m.nameList()
		_, _ = m.nameList()
		_, _ = m.nameList()
		_, _ = m.nameList()
		_, _ = m.nameList()
		_, _ = m.nameList()
		_, _ = m.str()
		_, _ = m.str()
		_, _ = m.str()
		_, _ = m.str()
		_, _ = m.boolv()
		_, _ = m.uint32()
	})
}

func FuzzVersionExchange(f *testing.F) {
	f.Add([]byte("SSH-2.0-test\r\n"))
	f.Add([]byte("banner\nSSH-2.0-test extra\r\n"))
	f.Add([]byte("SSH-1.99-old\r\n"))
	f.Add([]byte(strings.Repeat("x", 2048)))
	f.Add([]byte("SSH-2.0-bad\x1b[31m\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 80*1024 {
			return
		}
		c := &Client{
			cfg:  Config{Timeout: time.Second, Banner: func(string) {}},
			conn: &memConn{r: bytes.NewReader(nil), w: &bytes.Buffer{}},
			r:    bufio.NewReader(bytes.NewReader(data)),
		}
		_ = c.handshakeVersions()
	})
}
