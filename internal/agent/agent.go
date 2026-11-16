// Package agent talks to SSH private-key agents: PuTTY Pageant over its named
// pipe, and OpenSSH-style agents over a named pipe or AF_UNIX socket.
//
// The point of going through an agent is that winsh never has to read,
// decrypt, or hold a private key: it asks the agent to sign a blob.  That is
// both safer and the only practical way to support PuTTY-protected keys.
package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Agent protocol message numbers.
//
// These come from draft-miller-ssh-agent, which PuTTY's ssh.h agrees with
// byte for byte; they are not guesses.  Spelling that out matters because a
// wrong constant is invisible locally and baffling remotely.  winsh used to
// request the key list with message type 17, which is not
// SSH2_AGENTC_REQUEST_IDENTITIES at all but SSH2_AGENTC_ADD_IDENTITY, so every
// agent it spoke to tried to decode a private key out of a one-byte message and
// answered SSH_AGENT_FAILURE.  That presented as "Pageant holds no keys" while
// Pageant was healthy and ssh(1) was listing its key on the same pipe at the
// same moment, and it sent the investigation off hunting a client-identity
// check that never existed.  The values are therefore asserted against literal
// bytes in agent_fake_test.go rather than against these names.
const (
	agentFailure          = 5  // SSH_AGENT_FAILURE
	agentSuccess          = 6  // SSH_AGENT_SUCCESS
	requestIdentities     = 11 // SSH2_AGENTC_REQUEST_IDENTITIES
	identitiesAnswer      = 12 // SSH2_AGENT_IDENTITIES_ANSWER
	signRequest           = 13 // SSH2_AGENTC_SIGN_REQUEST
	signResponse          = 14 // SSH2_AGENT_SIGN_RESPONSE
	addIdentity           = 17 // SSH2_AGENTC_ADD_IDENTITY
	agentcExtension       = 27 // SSH2_AGENTC_EXTENSION
	agentExtensionFailure = 28 // SSH_AGENT_EXTENSION_FAILURE

	flagRsaSha2_256 = 2
	flagRsaSha2_512 = 4

	// extensionQuery is the standard extension name whose reply is the
	// agent's own list of supported extensions.  Both OpenSSH's agent and
	// Pageant implement it.
	extensionQuery = "query"
)

// PageantPipe is the named pipe PuTTY's Pageant listens on.
const PageantPipe = `\\.\pipe\pageant.pipe`

// WinSSHAgentPipe is the named pipe the OpenSSH agent shipped with Windows
// uses when SSH_AUTH_SOCK is not set.
const WinSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// ErrNoKeys reports that the agent understood the identity request and answered
// that it is holding no keys at all.  This is a different outcome from
// ErrRefused, and it deserves its own sentinel because the advice differs: the
// agent is healthy and reachable, there is simply nothing to sign with, so the
// user should load a key rather than debug the transport.
var ErrNoKeys = errors.New("agent holds no keys")

// ErrRefused reports that the agent answered the identity request with
// SSH_AGENT_FAILURE.  Pageant is not that shy: read from its source, an
// SSH2_AGENTC_REQUEST_IDENTITIES always earns an SSH2_AGENT_IDENTITIES_ANSWER,
// empty list included.  A refusal therefore means the agent disliked the
// request, which is worth saying out loud instead of blaming the agent for
// having nothing loaded.
var ErrRefused = errors.New("agent refused the identity request")

// ErrClosed is returned by every operation on a Client that has been closed.
var ErrClosed = errors.New("agent: connection closed")

// Identity is one key the agent can sign with.
type Identity struct {
	Blob    []byte
	Comment string
	Algo    string
}

// Client is a connection to one agent.
type Client struct {
	mu     sync.Mutex
	c      io.ReadWriteCloser
	name   string
	path   string
	closed bool
	// rbuf is the single read buffer used by exchange, sized to the reply
	// limit so that message-mode pipes never truncate a reply.  It is
	// allocated on first use because most sessions never reach an agent.
	rbuf []byte
	off  int
	// dead is set when an agent stopped answering; see readSome.
	dead bool
}

// Candidate is a location worth trying.
type Candidate struct {
	Name string
	Path string
	Kind string // "pipe" or "unix" or "env"
	// VerifyOwner requires the pipe to be owned by the user running winsh
	// before a single protocol byte is sent.  It is set for every candidate
	// whose name was discovered by searching the namespace rather than being
	// named by the user, because named pipes are machine-global and any local
	// process can create one that imitates an agent.
	VerifyOwner bool
}

// verifyPipeOwnership is supplied by the platform file.  Where named pipes do
// not exist it accepts anything, so that VerifyOwner cannot be silently
// satisfied on a platform that has no way to check it.
var verifyPipeOwnership = func(f *os.File) error { return nil }

// Candidates lists the agent endpoints to try, in the order a user would
// expect: the agent ssh(1) itself would use, then Pageant, then the Windows
// OpenSSH agent's default pipe.
func Candidates(env map[string]string) []Candidate {
	get := func(k string) string {
		if env != nil {
			return env[k]
		}
		return os.Getenv(k)
	}
	var out []Candidate
	if v := get("SSH_AUTH_SOCK"); v != "" {
		kind := "unix"
		if strings.HasPrefix(strings.ToLower(v), `\\.\pipe\`) || strings.HasPrefix(v, `\\`) {
			kind = "pipe"
		}
		out = append(out, Candidate{Name: "SSH_AUTH_SOCK=" + v, Path: v, Kind: kind})
	}
	out = append(out,
		Candidate{Name: "Pageant", Path: PageantPipe, Kind: "pipe"},
		Candidate{Name: "OpenSSH agent (Windows default)", Path: WinSSHAgentPipe, Kind: "pipe"})
	// Platform discovery, which on Windows finds the per-user Pageant pipe
	// whose name a client cannot reconstruct.  It is appended rather than
	// prepended so that an explicitly configured SSH_AUTH_SOCK always wins.
	out = append(out, platformCandidates()...)
	return out
}

// Dial connects to one candidate.
func Dial(cand Candidate) (*Client, error) {
	switch cand.Kind {
	case "pipe":
		f, err := dialPipe(cand.Path)
		if err != nil {
			return nil, fmt.Errorf("agent %s: %w", cand.Name, err)
		}
		if cand.VerifyOwner {
			// Checked on the handle that is about to carry the conversation.
			// Opening a second, throwaway handle to test ownership would
			// consume an instance from agents that publish only one, which is
			// how PuTTY's Pageant is built.
			if err := verifyPipeOwnership(f); err != nil {
				f.Close()
				return nil, fmt.Errorf("agent %s: %w", cand.Name, err)
			}
		}
		return &Client{c: f, name: cand.Name, path: cand.Path}, nil
	default:
		conn, err := net.DialTimeout("unix", cand.Path, 2*time.Second)
		if err != nil {
			return nil, fmt.Errorf("agent %s: %w", cand.Name, err)
		}
		return &Client{c: conn, name: cand.Name, path: cand.Path}, nil
	}
}

// ConnectFirst tries each candidate and returns the first agent that answers
// an identity request.
func ConnectFirst(env map[string]string) (*Client, []Candidate, error) {
	var tried []Candidate
	for _, cand := range Candidates(env) {
		tried = append(tried, cand)
		cl, err := Dial(cand)
		if err != nil {
			continue
		}
		if _, err := cl.Identities(); err != nil {
			cl.Close()
			continue
		}
		return cl, tried, nil
	}
	return nil, tried, fmt.Errorf("no SSH agent answered; tried %s", describe(tried))
}

// ConnectFirstReachable returns the first candidate that winsh could open a
// verified connection to, without requiring it to answer an identity request.
//
// ConnectFirst insists on a key listing, which is the right test before
// spending it on authentication but the wrong test for merely deciding whether
// an agent exists: Pageant answers SSH_AGENT_FAILURE rather than an empty list
// in several ordinary situations, and a caller that needs to know "is there an
// agent I can point another program at" must not be defeated by that.  Dial
// still bounds the wait and still proves ownership of any discovered pipe, so
// nothing about the trust model is weakened here.
func ConnectFirstReachable(env map[string]string) (*Client, []Candidate, error) {
	var tried []Candidate
	for _, cand := range Candidates(env) {
		tried = append(tried, cand)
		cl, err := Dial(cand)
		if err != nil {
			continue
		}
		return cl, tried, nil
	}
	return nil, tried, fmt.Errorf("no SSH agent could be reached; tried %s", describe(tried))
}

func describe(cs []Candidate) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name)
	}
	return strings.Join(names, ", ")
}

// Name identifies the agent for diagnostics.
func (c *Client) Name() string { return c.name }

// Path is the address the client connected to: the pipe name or socket path.
// It is exported because a caller may need to point a *different* program at
// the same agent, and re-discovering it independently risks trusting a pipe
// that this client never verified.
func (c *Client) Path() string { return c.path }

// Close ends the session with the agent.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.c.Close()
}

// maxAgentReply bounds what we will read from an agent: 1 MiB.  An agent is
// normally a trusted local process, but a hostile named pipe on the same
// machine should not be able to make winsh allocate without limit.
const maxAgentReply = 1 << 20

func (c *Client) exchange(req []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClosed
	}
	if c.dead {
		return nil, fmt.Errorf("agent %s: abandoned after it stopped answering", c.name)
	}
	if c.rbuf == nil {
		c.rbuf = make([]byte, maxAgentReply)
	}
	c.off = 0

	frame := make([]byte, 4+len(req))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(req)))
	copy(frame[4:], req)
	if _, err := c.c.Write(frame); err != nil {
		return nil, fmt.Errorf("agent %s: write: %w", c.name, err)
	}

	// The reply must be read with a buffer at least as large as the whole
	// message.  PuTTY's Pageant creates its pipe in message mode, where a read
	// that asks for fewer bytes than the message returns those bytes and
	// silently discards the rest of the message; reading the four-byte length
	// header on its own would therefore hang the client forever, because the
	// body that followed it is gone.  A stream-mode agent is served just as
	// well by the same loop, which keeps filling until the announced length
	// has arrived.
	//
	// The length prefix counts the body only, so a frame is four bytes longer
	// than the number stored in its header.
	for {
		if _, err := c.readSome(); err != nil {
			return nil, fmt.Errorf("agent %s: read: %w", c.name, err)
		}
		if c.off >= 4 {
			bodyLen := int(binary.BigEndian.Uint32(c.rbuf[:4]))
			if bodyLen < 1 || bodyLen > maxAgentReply-4 {
				return nil, fmt.Errorf("agent %s: implausible reply length %d", c.name, bodyLen)
			}
			if total := 4 + bodyLen; c.off >= total {
				return append([]byte(nil), c.rbuf[4:total]...), nil
			}
		}
		if c.off >= len(c.rbuf) {
			return nil, fmt.Errorf("agent %s: reply exceeded %d bytes", c.name, maxAgentReply)
		}
	}
}

// exchangeTimeout bounds one request/reply round trip.  An agent is a separate
// process that may be wedged behind a modal dialog or busy serving another
// client, and winsh must not inherit that stall: it is listing options, not
// negotiating a treaty.
const exchangeTimeout = 3 * time.Second

// readSome performs one read under a deadline.  If the agent stops answering,
// the client is marked dead and its handle is deliberately left open rather
// than closed: tearing down an os.File while a blocked read still refers to it
// would pull the descriptor out from under that read.  One leaked handle per
// wedged candidate is the safe trade, and discovery bounds how many candidates
// there can be.
func (c *Client) readSome() (int, error) {
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	buf := c.rbuf[c.off:]
	go func() {
		n, err := c.c.Read(buf)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		c.off += r.n
		return r.n, r.err
	case <-time.After(exchangeTimeout):
		c.dead = true
		return 0, fmt.Errorf("no reply within %v", exchangeTimeout)
	}
}

// Identities asks the agent for its key list.
func (c *Client) Identities() ([]Identity, error) {
	reply, err := c.exchange([]byte{requestIdentities})
	if err != nil {
		return nil, err
	}
	return parseIdentitiesReply(reply, c.name)
}

func parseIdentitiesReply(reply []byte, name string) ([]Identity, error) {
	if len(reply) == 0 {
		return nil, errors.New("agent: empty reply")
	}
	if reply[0] == agentFailure {
		return nil, fmt.Errorf("agent %s: %w", name, ErrRefused)
	}
	if reply[0] != identitiesAnswer {
		return nil, fmt.Errorf("agent %s: unexpected reply type %d", name, reply[0])
	}
	r := &reader{b: reply[1:]}
	count, ok := r.uint32()
	if !ok {
		return nil, errors.New("agent: malformed identity list")
	}
	if count > 4096 {
		return nil, fmt.Errorf("agent: implausible identity count %d", count)
	}
	// An empty list is a perfectly good answer, and it is the agent saying so
	// rather than refusing to say anything.  It is reported separately from
	// ErrRefused so that --list-keys can tell "load a key" from "your agent is
	// broken".
	if count == 0 {
		return nil, fmt.Errorf("agent %s: %w", name, ErrNoKeys)
	}
	var out []Identity
	for i := uint32(0); i < count; i++ {
		blob, ok := r.string()
		if !ok {
			return nil, errors.New("agent: malformed key blob")
		}
		comment, ok := r.string()
		if !ok {
			return nil, errors.New("agent: malformed comment")
		}
		algo, err := AlgoOf(blob)
		if err != nil {
			continue // an algorithm we do not implement is simply not usable
		}
		out = append(out, Identity{Blob: blob, Comment: string(comment), Algo: algo})
	}
	return out, nil
}

// Sign asks the agent to sign data with key.  For RSA keys the request selects
// rsa-sha2-256 or rsa-sha2-512 explicitly; a legacy agent that only knows
// ssh-rsa is retried once without the flag.
// Sign asks the agent to sign data with key, using the key's preferred
// signature algorithm.
func (c *Client) Sign(blob, data []byte) ([]byte, error) {
	return c.SignWithAlgo(blob, data, "")
}

// SignWithAlgo asks the agent to sign data and return a signature in the named
// algorithm. sigAlgo may be empty to let the agent choose.
//
// The distinction matters: an ssh-rsa key can produce ssh-rsa (SHA-1),
// rsa-sha2-256 or rsa-sha2-512, and which one comes back is decided by the
// flags word in the request, not by anything else. Offering rsa-sha2-512 in the
// userauth packet while quietly accepting an rsa-sha2-256 signature from the
// agent makes the server reject the key with no explanation, because the
// signature blob disagrees with the algorithm the request named.
func (c *Client) SignWithAlgo(blob, data []byte, sigAlgo string) ([]byte, error) {
	algo, err := AlgoOf(blob)
	if err != nil {
		return nil, err
	}
	flags := uint32(0)
	if sigAlgo != "" && !signatureAlgoAllowed(sigAlgo, algo) {
		// Refuse here rather than let the agent answer: a signature whose
		// algorithm disagrees with the userauth packet carrying it is reported
		// by the server as "key rejected", which points the finger at the key
		// rather than at the bug.
		return nil, fmt.Errorf("agent %s: cannot sign %s with a %s key", c.name, sigAlgo, algo)
	}
	switch sigAlgo {
	case "rsa-sha2-256":
		flags = flagRsaSha2_256
	case "rsa-sha2-512":
		flags = flagRsaSha2_512
	case "":
		// No preference stated: pick a SHA-2 variant for RSA rather than the
		// SHA-1 ssh-rsa that modern servers refuse outright.
		switch algo {
		case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
			flags = flagRsaSha2_256
		}
	}
	reply, err := c.signOnce(blob, data, flags)
	if err != nil {
		return nil, err
	}
	if len(reply) == 0 {
		return nil, errors.New("agent: empty signature reply")
	}
	if reply[0] == agentFailure && sigAlgo == "" && flags != 0 {
		// Older agents (notably some Pageant builds) reject the SHA-2 flag.
		return c.signOnce(blob, data, 0)
	}
	if reply[0] != signResponse {
		return nil, fmt.Errorf("agent %s: refused to sign (reply type %d)", c.name, reply[0])
	}
	r := &reader{b: reply[1:]}
	sig, ok := r.string()
	if !ok {
		return nil, errors.New("agent: malformed signature")
	}
	if want := signatureAlgo(sig); sigAlgo != "" && want != sigAlgo {
		return nil, fmt.Errorf("agent %s: asked for %s but returned %s", c.name, sigAlgo, want)
	}
	return sig, nil
}

// signatureAlgoAllowed reports whether a key of type keyAlgo may produce
// signatures named sigAlgo.  RSA keys are the only ones with a choice.
func signatureAlgoAllowed(sigAlgo, keyAlgo string) bool {
	rsa := map[string]bool{"ssh-rsa": true, "rsa-sha2-256": true, "rsa-sha2-512": true}
	if rsa[keyAlgo] {
		return rsa[sigAlgo]
	}
	return sigAlgo == keyAlgo
}

// signatureAlgo reports the algorithm named inside an SSH signature blob, or
// the empty string if it cannot be read.
func signatureAlgo(sig []byte) string {
	r := &reader{b: sig}
	s, ok := r.string()
	if !ok {
		return ""
	}
	return string(s)
}

func (c *Client) signOnce(blob, data []byte, flags uint32) ([]byte, error) {
	req := make([]byte, 0, 32+len(blob)+len(data))
	req = append(req, signRequest)
	req = appendString(req, blob)
	req = appendString(req, data)
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], flags)
	req = append(req, f[:]...)
	return c.exchange(req)
}

// AlgoOf extracts the algorithm name from a public-key blob.
func AlgoOf(blob []byte) (string, error) {
	r := &reader{b: blob}
	algo, ok := r.string()
	if !ok || len(algo) == 0 || len(algo) > 64 {
		return "", errors.New("agent: malformed key blob")
	}
	return string(algo), nil
}

// Extensions asks the agent to list the agent extensions it understands, using
// the standard "query" extension request that both OpenSSH's agent and Pageant
// implement.  An agent too old to negotiate extensions returns an error, which
// is a fact rather than a fault: callers must treat "unknown" as unknown.
//
// The extension data field is sent even though it is empty.  Pageant reads the
// name and then whatever each handler wants, and a truncated request is the kind
// of thing that makes an implementation disagree with you later.
func (c *Client) Extensions() ([]string, error) {
	req := []byte{agentcExtension}
	req = appendString(req, []byte(extensionQuery))
	req = appendString(req, nil)
	reply, err := c.exchange(req)
	if err != nil {
		return nil, err
	}
	if len(reply) == 0 {
		return nil, errors.New("agent: empty extension reply")
	}
	// Pageant reserves SSH_AGENT_FAILURE for "I have never heard of that
	// extension name" and uses SSH_AGENT_EXTENSION_FAILURE for "I know the
	// name but could not carry it out", so either way the answer to this
	// question is that the agent does not implement query.
	if reply[0] == agentFailure || reply[0] == agentExtensionFailure {
		return nil, fmt.Errorf("agent %s: does not implement the query extension", c.name)
	}
	if reply[0] != agentSuccess {
		return nil, fmt.Errorf("agent %s: unexpected extension reply type %d", c.name, reply[0])
	}
	// The body is a bare sequence of strings to the end of the message, with
	// no count field.  Anything that does not look like a name is treated as
	// the end of the list rather than as an error, so that one agent padding
	// its reply cannot make the whole listing useless.
	var out []string
	r := &reader{b: reply[1:]}
	for !r.done() {
		s, ok := r.string()
		if !ok || !plausibleExtensionName(s) {
			break
		}
		out = append(out, string(s))
	}
	return out, nil
}

// plausibleExtensionName bounds what will be believed as an extension name from
// a local but not necessarily trustworthy named pipe.
func plausibleExtensionName(s []byte) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, b := range s {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

// SupportRsaSha2 reports whether the agent advertises rsa-sha2 support.
//
// A false answer is not fatal: the authoritative test is Sign, which retries
// without the SHA-2 flag for agents that only understand the legacy ssh-rsa
// algorithm.  This is a fast-path hint, and it is implemented against the
// documented extension negotiation rather than a name invented for the purpose,
// which could only ever have produced a negative answer.
func (c *Client) SupportRsaSha2() bool {
	exts, err := c.Extensions()
	if err != nil {
		return false
	}
	for _, e := range exts {
		switch e {
		case "rsa-sha2-512-support@openssh.com", "rsa-sha2-256-support@openssh.com":
			return true
		}
	}
	return false
}

func appendString(dst []byte, s []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	dst = append(dst, l[:]...)
	return append(dst, s...)
}

// reader is a bounds-checked SSH string/list reader.  Every access is checked
// so that a malformed agent reply cannot cause a panic or read out of bounds.
type reader struct {
	b   []byte
	off int
}

func (r *reader) uint32() (uint32, bool) {
	if r.off+4 > len(r.b) || r.off < 0 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, true
}

func (r *reader) string() ([]byte, bool) {
	n, ok := r.uint32()
	if !ok || n > uint32(len(r.b)-r.off) {
		return nil, false
	}
	out := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return out, true
}

func (r *reader) bytes(n uint32) ([]byte, bool) {
	if n > uint32(len(r.b)-r.off) {
		return nil, false
	}
	out := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return out, true
}

func (r *reader) done() bool { return r.off >= len(r.b) }
