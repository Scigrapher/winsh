package bootstrap

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"winsh/internal/cli"
)

func FuzzParseBootstrap(f *testing.F) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))[:22]
	f.Add([]byte("MOSH CONNECT 60000 " + key + "\n"))
	f.Add([]byte("MOSH IP 127.0.0.1\nMOSH CONNECT 60001 " + key + "\n"))
	f.Add([]byte("server chatter\nMOSH CONNECT 60002 " + key + "\n"))
	f.Add([]byte("MOSH CONNECT 70000 invalid\n"))
	f.Add([]byte("\x1b]52;c;secret\x07"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		cfg := &cli.Config{
			Host:   "127.0.0.1",
			Family: "prefer-inet",
		}
		_, _ = parseBootstrapTo(bytes.NewReader(data), cfg, Options{}, io.Discard)
	})
}
