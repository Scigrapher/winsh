package ssh

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"
)

func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

func TestKexReplyReadErrorAbortsHandshake(t *testing.T) {
	var init builder
	init.byte_(msgKexInit)
	init.raw(make([]byte, 16))
	init.strs(kexAlgorithms)
	init.strs(hostKeyAlgorithms)
	init.strs(cipherAlgorithms)
	init.strs(cipherAlgorithms)
	init.strs(macAlgorithms)
	init.strs(macAlgorithms)
	init.strs([]string{"none"})
	init.strs([]string{"none"})
	init.strs(nil)
	init.strs(nil)
	init.boolv(false)
	init.uint32(0)
	initPacket, err := framePacket(init.b, 8, 0)
	if err != nil {
		t.Fatal(err)
	}

	var disconnect builder
	disconnect.byte_(msgDisconnect)
	disconnect.uint32(disconnectProtocolError)
	disconnect.str([]byte("protocol error"))
	disconnect.str(nil)
	disconnectPacket, err := framePacket(disconnect.b, 8, 0)
	if err != nil {
		t.Fatal(err)
	}

	wire := append(initPacket, disconnectPacket...)
	c := &Client{
		conn:          &memConn{r: bytes.NewReader(wire), w: &bytes.Buffer{}},
		r:             bufio.NewReader(bytes.NewReader(wire)),
		localVersion:  "SSH-2.0-winsh-test",
		remoteVersion: "SSH-2.0-server-test",
	}
	if err := c.kex(); err == nil {
		t.Fatal("kex reported success after a disconnect instead of a KEX reply")
	}
	if c.out != nil || c.in != nil {
		t.Fatal("kex installed cipher state after a failed exchange")
	}
}

func TestVersionLineIsCappedBeforeAllocation(t *testing.T) {
	data := strings.Repeat("x", maxPreVersionLine+1)
	c := &Client{
		conn: &memConn{r: bytes.NewReader(nil), w: &bytes.Buffer{}},
		r:    bufio.NewReader(strings.NewReader(data)),
	}
	if err := c.handshakeVersions(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("over-long version line error = %v", err)
	}
}

func TestPreVersionBannerTotalIsCapped(t *testing.T) {
	line := strings.Repeat("a", 1000) + "\n"
	data := strings.Repeat(line, maxPreVersionBytes/len(line)+2)
	c := &Client{
		conn: &memConn{r: bytes.NewReader(nil), w: &bytes.Buffer{}},
		r:    bufio.NewReader(strings.NewReader(data)),
	}
	if err := c.handshakeVersions(); err == nil || !strings.Contains(err.Error(), "too much") {
		t.Fatalf("over-long pre-version banner error = %v", err)
	}
}

func TestIdentificationLineRejectsControls(t *testing.T) {
	c := &Client{
		conn: &memConn{r: bytes.NewReader(nil), w: &bytes.Buffer{}},
		r:    bufio.NewReader(strings.NewReader("SSH-2.0-bad\x1b[31m\r\n")),
	}
	if err := c.handshakeVersions(); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("control-bearing identification error = %v", err)
	}
}

func TestPreVersionBannerIsSanitized(t *testing.T) {
	var banner string
	c := &Client{
		cfg:  Config{Banner: func(s string) { banner += s }},
		conn: &memConn{r: bytes.NewReader(nil), w: &bytes.Buffer{}},
		r:    bufio.NewReader(strings.NewReader("bad\x1b]52;c;secret\x07\nSSH-2.0-good\r\n")),
	}
	if err := c.handshakeVersions(); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(banner, "\x1b\x07") || !strings.Contains(banner, `\x1b`) {
		t.Fatalf("unsafe pre-version banner = %q", banner)
	}
}

func TestChannelReceiveBufferHasHardLimit(t *testing.T) {
	ch := &Channel{}
	if err := ch.appendData(make([]byte, maxChannelBuffer)); err != nil {
		t.Fatal(err)
	}
	if err := ch.appendData([]byte{0}); err == nil {
		t.Fatal("channel buffer accepted data beyond its hard limit")
	}
}

func TestRemoteProtocolErrorIsSanitized(t *testing.T) {
	got := (&Error{Code: 2, Message: "bad\x1b]52;c;secret\x07\nwinsh: fake"}).Error()
	if strings.ContainsAny(got, "\x1b\x07\n") {
		t.Fatalf("remote protocol error contains terminal controls: %q", got)
	}
}
