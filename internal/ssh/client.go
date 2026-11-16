package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"winsh/internal/keys"
	"winsh/internal/textsafe"
)

// Config describes a bootstrap connection.
type Config struct {
	// Addr is the numeric or DNS address to dial; Host is the name used for
	// known_hosts (they differ when --experimental-remote-ip resolves first).
	Addr string
	Host string
	Port int
	User string

	Timeout time.Duration

	// Signers are offered for publickey authentication, in preference order.
	Signers []keys.Signer

	// KnownHostFiles defaults to $HOME/.ssh/known_hosts.
	KnownHostFiles []string
	// StrictHostKey rejects unknown hosts instead of trusting them on first
	// use.  It is on by default; turning it off is a security downgrade.
	StrictHostKey bool
	// HostKeyCallback, when set, is consulted for hosts that are not in
	// known_hosts; returning true accepts the key (trust on first use).
	HostKeyCallback func(addr string, k keys.PubKey) bool
	// AllowSHA1HostKey permits legacy ssh-rsa host keys.
	AllowSHA1HostKey bool

	// Prompt collects a password for password / keyboard-interactive auth.
	Prompt func(label string, echo bool) (string, error)

	// Verbose writes protocol traces to stderr.
	Verbose bool

	// Banner receives SSH_MSG_USERAUTH_BANNER text.
	Banner func(string)
}

func (c *Config) host() string {
	if c.Host != "" {
		return c.Host
	}
	return c.Addr
}

// Client is one SSH connection.
type Client struct {
	cfg Config

	conn net.Conn
	r    *bufio.Reader

	in, out *direction

	localVersion, remoteVersion string
	sessionID                   []byte
	hostKey                     keys.PubKey
	kexAlgo                     string
	hostKeyAlgo                 string
	outCipherName               string
	inCipherName                string
	outMacName                  string
	inMacName                   string

	// sendSeq and recvSeq are the MAC packet counters.  They count every
	// packet in each direction for the life of the transport and are reset
	// at keying only when the peer negotiated RFC 9142 strict key exchange;
	// classic OpenSSH never resets them, so a client that always starts from
	// zero MACs its first encrypted packet with the wrong number and is
	// dropped without a diagnostic.  See kex() for the reset.
	sendSeq, recvSeq uint32
	kexStrict        bool

	channels map[uint32]*Channel
	nextChan uint32

	closed bool
}

// Channel is an opened "session" channel.
type Channel struct {
	id        uint32
	remoteID  uint32
	recvWin   uint32
	maxPacket uint32
	c         *Client

	// buf holds stdout data received but not yet handed to the reader;
	// consumed counts bytes since the last window adjustment.
	buf      []byte
	consumed uint32
	stderr   []byte
	closed   bool
	eof      bool

	// replies queues CHANNEL_SUCCESS/CHANNEL_FAILURE bytes whose channel id
	// matches this channel. They are collected by the same reader that
	// collects data because a request reply and a window adjustment and the
	// first output line can arrive in any order, and reading them on two
	// different code paths means whichever path runs first steals the other
	// one's packet.
	replies []byte
}

// Errors surfaced by this package.
var (
	ErrHostKeyUnknown  = errors.New("ssh: host key is not in known_hosts")
	ErrHostKeyChanged  = errors.New("ssh: HOST KEY HAS CHANGED - possible man-in-the-middle attack")
	ErrHostKeyRevoked  = errors.New("ssh: host key is marked @revoked in known_hosts")
	ErrKexIncomplete   = errors.New("ssh: key exchange did not complete")
	ErrNoAuthMethods   = errors.New("ssh: no authentication method succeeded")
	ErrUnsupported     = errors.New("ssh: no algorithm overlap")
	ErrChannelRejected = errors.New("ssh: server rejected the channel")
	ErrDisconnected    = errors.New("ssh: connection closed by peer")
)

// maxPacketBytes bounds the framing layer so a hostile server cannot make the
// client allocate an arbitrarily large packet.
const maxPacketBytes = 256 * 1024

// Connect performs TCP connect, version exchange, key exchange, and
// authentication.
func Connect(cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.KnownHostFiles == nil {
		if home, err := os.UserHomeDir(); err == nil {
			cfg.KnownHostFiles = []string{home + "/.ssh/known_hosts"}
		}
	}
	address := net.JoinHostPort(cfg.Addr, fmt.Sprint(cfg.Port))
	conn, err := net.DialTimeout("tcp", address, cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", address, err)
	}
	c := &Client{cfg: cfg, conn: conn, r: bufio.NewReader(conn), channels: map[uint32]*Channel{}}
	if err := c.handshakeVersions(); err != nil {
		c.Close()
		return nil, err
	}
	if err := c.kex(); err != nil {
		c.Close()
		return nil, err
	}
	if c.in == nil || c.out == nil || len(c.sessionID) == 0 || len(c.hostKey.Blob) == 0 {
		c.Close()
		return nil, ErrKexIncomplete
	}
	if err := c.authenticate(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Close tears down the connection.
func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// HostKey reports the verified server host key.
func (c *Client) HostKey() keys.PubKey { return c.hostKey }

// SessionID returns the negotiated session identifier.
func (c *Client) SessionID() []byte { return append([]byte(nil), c.sessionID...) }

func (c *Client) log(format string, args ...any) {
	if c.cfg.Verbose {
		fmt.Fprintln(os.Stderr, "winsh ssh: "+textsafe.Line(fmt.Sprintf(format, args...), 4096))
	}
}

// ---------- version exchange ----------

const (
	maxPreVersionLine  = 1024
	maxPreVersionBytes = 64 * 1024
	maxVersionLine     = 255
)

func (c *Client) handshakeVersions() error {
	c.localVersion = "SSH-2.0-winsh_" + versionString
	if _, err := c.conn.Write([]byte(c.localVersion + "\r\n")); err != nil {
		return fmt.Errorf("ssh: version write: %w", err)
	}
	deadline := time.Now().Add(c.cfg.Timeout)
	_ = c.conn.SetReadDeadline(deadline)
	_ = c.conn.SetWriteDeadline(deadline)
	limit := 512
	total := 0
	for {
		line, err := readCappedLine(c.r, maxPreVersionLine)
		if err != nil {
			return fmt.Errorf("ssh: version read: %w", err)
		}
		total += len(line)
		if total > maxPreVersionBytes {
			return errors.New("ssh: too much pre-version banner data")
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			if len(line) > maxVersionLine {
				return errors.New("ssh: remote version line is too long")
			}
			if !validIdentificationLine(line) {
				return errors.New("ssh: remote version line contains control characters")
			}
			c.remoteVersion = line
			if !strings.HasPrefix(line, "SSH-2.0") && !strings.HasPrefix(line, "SSH-1.99") {
				return fmt.Errorf("ssh: unsupported remote version %q", line)
			}
			c.log("remote version %s", line)
			return nil
		}
		limit--
		if limit <= 0 {
			return errors.New("ssh: too much pre-version banner data")
		}
		// Banner lines from the server; show them, they are user-facing.
		if c.cfg.Banner != nil && line != "" {
			c.cfg.Banner(textsafe.Terminal(line, 4096))
		}
	}
}

func readCappedLine(r *bufio.Reader, max int) (string, error) {
	var out []byte
	for {
		frag, err := r.ReadSlice('\n')
		if len(frag) > 0 {
			if len(out)+len(frag) > max {
				return "", fmt.Errorf("ssh: line exceeds %d bytes", max)
			}
			out = append(out, frag...)
		}
		switch {
		case err == nil:
			return string(out), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", err
		}
	}
}

func validIdentificationLine(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

const versionString = "1.0"

// ---------- packet layer ----------

// writePacket frames, encrypts, authenticates, and sends one payload.
func (c *Client) writePacket(payload []byte) error {
	if c.out == nil {
		// Plaintext phase: no encryption, but the framing is identical.
		return c.writePlain(payload)
	}
	aadlen := 0
	if c.out.etm {
		aadlen = 4
	}
	packet, err := framePacket(payload, c.out.blockSize, aadlen)
	if err != nil {
		return err
	}
	if c.out.mac == nil {
		return errors.New("ssh: internal error: encrypted with no MAC")
	}

	// Encrypt, then authenticate -- but "authenticate" means different bytes
	// for the two families, and for -etm the four-byte length field is not
	// encrypted at all and does not consume keystream. See readPacket.
	enc := make([]byte, len(packet))
	copy(enc, packet)
	if c.out.etm {
		c.out.ctr.XORKeyStream(enc[4:], enc[4:])
	} else {
		c.out.ctr.XORKeyStream(enc, enc)
	}

	var seq [4]byte
	binaryPutUint32(seq[:], c.sendSeq)
	c.out.mac.Reset()
	c.out.mac.Write(seq[:])
	if c.out.etm {
		c.out.mac.Write(packet[:4]) // clear length, authenticated as AAD
		c.out.mac.Write(enc[4:])
	} else {
		c.out.mac.Write(packet) // encrypt-and-MAC authenticates the plaintext
	}
	macOut := c.out.mac.Sum(nil)

	if _, err := c.conn.Write(enc); err != nil {
		return err
	}
	if _, err := c.conn.Write(macOut); err != nil {
		return err
	}
	c.sendSeq++
	return nil
}

// framePacket builds one unencrypted SSH packet: the four-byte length, the
// one-byte padding length, the payload, and padding, with the whole thing a
// multiple of blockSize and at least minBytes long overall.
//
// The minimum matters: a bare SSH_MSG_NEWKEYS is five bytes, and OpenSSH
// complains about encrypted packets that short because they are trivially
// identifiable by length.  Padding it out is free and removes the complaint.
// framePacket builds one SSH packet: the four-byte length, the one-byte
// padding length, the payload, and padding.
//
// blockSize and aadlen are not free parameters; they reproduce what the peer's
// reader will demand. OpenSSH checks
//
//	if (need % block_size != 0) { logit("padding error"); drop the connection }
//
// with need being the encrypted part of the packet: the whole thing including
// the length field for an encrypt-and-MAC suite, but the length field excluded
// for an encrypt-then-MAC suite, where those four bytes travel in the clear.
// Producing packets that are merely "a multiple of eight" therefore gets the
// connection dropped with no protocol message to explain it, which is a
// genuinely miserable thing to debug.
//
// The 16-byte floor keeps SSH_MSG_NEWKEYS from being identifiable by length,
// which is a recommendation rather than a requirement.
func framePacket(payload []byte, blockSize, aadlen int) ([]byte, error) {
	if blockSize < 8 {
		blockSize = 8
	}
	if aadlen != 0 && aadlen != 4 {
		return nil, fmt.Errorf("ssh: internal error: bad aadlen %d", aadlen)
	}
	padLen := blockSize - ((4 + 1 + len(payload) - aadlen) % blockSize)
	if padLen < 4 {
		padLen += blockSize
	}
	for 4+1+len(payload)+padLen < 16 {
		padLen += blockSize
	}
	packet := make([]byte, 4+1+len(payload)+padLen)
	binaryPutUint32(packet, uint32(1+len(payload)+padLen))
	packet[4] = byte(padLen)
	copy(packet[5:], payload)
	pad := make([]byte, padLen)
	if err := randomBytes(pad); err != nil {
		return nil, err
	}
	copy(packet[5+len(payload):], pad)
	return packet, nil
}

func (c *Client) writePlain(payload []byte) error {
	// Before any keys are in play the block size is the protocol minimum of
	// eight and nothing is excluded from encryption.
	packet, err := framePacket(payload, 8, 0)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(packet)
	return err
}

// readPacket receives, authenticates, and decrypts one payload.
// readPacket receives, authenticates, and decrypts one payload.
//
// The two MAC families differ in more than the order of the operations, and
// OpenSSH's source is unusually blunt about it:
//
//	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;
//	len -= aadlen; /* packet length is not encrypted for EtM modes */
//
// So with an -etm suite the four-byte packet-length field travels in the clear,
// is authenticated as additional data, and -- importantly -- does not consume
// keystream, because the CTR keystream starts at the body. Without -etm the
// whole packet including its length is encrypted and the tag covers the
// plaintext, which is why the family is called encrypt-and-MAC.
func (c *Client) readPacket() ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c.r, hdr); err != nil {
		return nil, err
	}
	hdrPlain := make([]byte, 4)
	copy(hdrPlain, hdr)

	var packetLen uint32
	if c.in == nil {
		// Plaintext phase.
		packetLen = binaryLoadUint32(hdr)
	} else if c.in.etm {
		packetLen = binaryLoadUint32(hdr)
	} else {
		c.in.ctr.XORKeyStream(hdrPlain, hdrPlain)
		packetLen = binaryLoadUint32(hdrPlain)
	}
	if packetLen < 5 || packetLen > maxPacketBytes {
		return nil, fmt.Errorf("ssh: implausible packet length %d", packetLen)
	}
	// There is deliberately no check here that the packet length is a
	// multiple of the cipher block size. OpenSSH's reader imposes none either:
	// for the -etm suites the length field is not even encrypted, so its
	// value and the total are aligned differently again, and insisting on an
	// alignment the peer does not promise only breaks working connections.
	// The bounds check above is the part that matters, because it happens
	// before the allocation.

	encBody := make([]byte, packetLen)
	if _, err := io.ReadFull(c.r, encBody); err != nil {
		return nil, err
	}
	body := make([]byte, packetLen)
	defer wipeBytes(body)
	defer wipeBytes(encBody)
	copy(body, encBody)
	if c.in != nil {
		c.in.ctr.XORKeyStream(body, body)
	}

	if c.in != nil && c.in.mac != nil {
		tag := make([]byte, c.in.mac.Size())
		if _, err := io.ReadFull(c.r, tag); err != nil {
			return nil, err
		}
		var seq [4]byte
		binaryPutUint32(seq[:], c.recvSeq)
		c.in.mac.Reset()
		c.in.mac.Write(seq[:])
		if c.in.etm {
			// AAD (the clear length) plus ciphertext.
			c.in.mac.Write(hdr)
			c.in.mac.Write(encBody)
		} else {
			// Encrypt-and-MAC authenticates the plaintext packet.
			c.in.mac.Write(hdrPlain)
			c.in.mac.Write(body)
		}
		if !hmacEqual(c.in.mac.Sum(nil), tag) {
			return nil, fmt.Errorf("ssh: authentication tag mismatch at receive sequence %d (length %d, etm %v)",
				c.recvSeq, packetLen, c.in.etm)
		}
	}

	padLen := int(body[0])
	if padLen < 4 || padLen > len(body)-1 {
		return nil, errors.New("ssh: bad padding length")
	}
	payload := make([]byte, len(body)-1-padLen)
	copy(payload, body[1:])
	if c.in != nil {
		c.recvSeq++
	}
	return payload, nil
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// binaryPutUint32/binaryLoadUint32 keep the framing readable.
func binaryPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func binaryLoadUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// readLoop services packets that are not addressed to a channel.
func (c *Client) expect(want ...byte) ([]byte, error) {
	for {
		p, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			return nil, errors.New("ssh: empty packet")
		}
		t := p[0]
		switch t {
		case msgDisconnect:
			m := &msg{b: p[1:]}
			code, _ := m.uint32()
			desc, _ := m.str()
			return nil, &Error{Code: int(code), Message: string(desc)}
		// EXT_INFO is a courtesy announcement the server may make whenever
		// the client asked for ext-info-c; it is not a reply to anything, so it
		// must be skipped the same way as an IGNORE.
		case msgIgnore, msgUnimplemented, msgExtInfo:
			continue
		case msgDebug:
			m := &msg{b: p[1:]}
			_, _ = m.boolv()
			s, _ := m.str()
			c.log("debug: %s", s)
			continue
		}
		for _, w := range want {
			if t == w {
				return p, nil
			}
		}
		return nil, fmt.Errorf("%w: expected %v, got message %d", ErrUnsupported, want, t)
	}
}
