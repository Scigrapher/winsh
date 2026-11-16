package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeAgent is an in-process SSH agent that lets the client half of the
// protocol be tested deterministically, without depending on Pageant or
// ssh-agent being installed and running.
//
// Its message numbers are written as literal bytes on purpose, and they are the
// numbers from the specification rather than the names declared in this package.
// If a test helper matched on requestIdentities the way the client sends it,
// then a wrong constant would simply move the bug into both halves at once: the
// client would ask for the wrong message and the fake would faithfully answer
// the wrong question.  That is exactly how winsh spent days believing that
// Pageant refused to list keys -- it was sending 17, SSH2_AGENTC_ADD_IDENTITY,
// instead of 11, SSH2_AGENTC_REQUEST_IDENTITIES, and every test still passed.
type fakeAgent struct {
	c net.Conn

	mu       sync.Mutex
	requests [][]byte // request bodies, in the order they arrived
	keys     []Identity
	signed   int
	bad      int

	// extensionReply is the body sent for an extension request.  The default
	// is SSH_AGENT_EXTENSION_FAILURE, which is what an agent that has never
	// heard of "query" sends.
	extensionReply []byte

	// refuseIdentities makes the agent answer the identity request with a bare
	// SSH_AGENT_FAILURE, which is how a hostile or confused agent behaves, and
	// is a different condition from holding no keys.
	refuseIdentities bool

	// signFlags records the flags word of every sign request, so a test can
	// check that the client asked for the algorithm it meant to ask for.
	signFlags []uint32
	// signAlgorithm names the algorithm the fake puts in the signature it
	// returns.  Setting it to something other than what was asked for is how
	// the client is tested for noticing.
	signAlgorithm string
}

func newFakeAgent(t *testing.T, keys []Identity) (*fakeAgent, net.Conn) {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	f := &fakeAgent{c: serverEnd, keys: keys}
	go f.serve()
	return f, clientEnd
}

func (f *fakeAgent) serve() {
	defer f.c.Close()
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(f.c, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr)
		if n == 0 || n > 1<<20 {
			return
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(f.c, req); err != nil {
			return
		}
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.mu.Unlock()

		switch req[0] {
		case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
			if f.refuseIdentities {
				f.reply([]byte{5}) // SSH_AGENT_FAILURE
				continue
			}
			body := []byte{12} // SSH2_AGENT_IDENTITIES_ANSWER
			var count [4]byte
			binary.BigEndian.PutUint32(count[:], uint32(len(f.keys)))
			body = append(body, count[:]...)
			for _, id := range f.keys {
				body = appendString(body, id.Blob)
				body = appendString(body, []byte(id.Comment))
			}
			f.reply(body)
		case 13: // SSH2_AGENTC_SIGN_REQUEST
			r := &reader{b: req[1:]}
			if _, ok := r.string(); !ok {
				f.reply([]byte{5})
				continue
			}
			if _, ok := r.string(); !ok {
				f.reply([]byte{5})
				continue
			}
			flags, _ := r.uint32()
			f.mu.Lock()
			f.signed++
			f.signFlags = append(f.signFlags, flags)
			algo := f.signAlgorithm
			f.mu.Unlock()
			if algo == "" {
				f.reply([]byte{5}) // SSH_AGENT_FAILURE
				continue
			}
			body := []byte{14} // SSH2_AGENT_SIGN_RESPONSE
			body = appendString(body, appendString(nil, []byte(algo)))
			body = append(body, bytes.Repeat([]byte{0x77}, 8)...)
			f.reply(body)
		case 27: // SSH2_AGENTC_EXTENSION
			if f.extensionReply != nil {
				f.reply(f.extensionReply)
			} else {
				f.reply([]byte{28}) // SSH_AGENT_EXTENSION_FAILURE
			}
		default:
			f.mu.Lock()
			f.bad++
			f.mu.Unlock()
			f.reply([]byte{5})
		}
	}
}

func (f *fakeAgent) reply(body []byte) {
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	_, err := f.c.Write(frame)
	if err != nil {
		f.c.SetDeadline(time.Now())
	}
}

// seen returns the request bodies the agent received, oldest first.
func (f *fakeAgent) seen() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.requests))
	copy(out, f.requests)
	return out
}

func (f *fakeAgent) countBad() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bad
}

func testBlob(algo string) []byte {
	return appendString(appendString(nil, []byte(algo)), []byte("0123456789abcdef0123456789abcdef"))
}

// TestWireContract pins the bytes that leave winsh.  This is the test that
// would have caught the identity-request bug, and it deliberately compares
// against literals instead of the package constants.
func TestWireContract(t *testing.T) {
	blob := testBlob("ssh-ed25519")
	f, conn := newFakeAgent(t, []Identity{{Blob: blob, Comment: "c"}})
	cl := &Client{c: conn, name: "fake", rbuf: make([]byte, maxAgentReply)}
	defer cl.Close()

	if _, err := cl.Identities(); err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if _, err := cl.Sign(blob, []byte("session id")); err == nil {
		t.Fatal("expected the fake agent to refuse to sign")
	}
	cl.Extensions()

	got := f.seen()
	if len(got) != 3 {
		t.Fatalf("agent saw %d requests, want 3", len(got))
	}
	if want := []byte{11}; !bytesEqual(got[0], want) {
		t.Errorf("identity request on the wire = %v, want %v (SSH2_AGENTC_REQUEST_IDENTITIES)", got[0], want)
	}
	if got[1][0] != 13 {
		t.Errorf("sign request on the wire starts with %d, want 13 (SSH2_AGENTC_SIGN_REQUEST)", got[1][0])
	}
	if got[2][0] != 27 {
		t.Errorf("extension request on the wire starts with %d, want 27 (SSH2_AGENTC_EXTENSION)", got[2][0])
	}
	// A request must carry no trailing garbage: the length prefix and the body
	// have to agree exactly, or the agent will read the next message as data.
	if f.countBad() != 0 {
		t.Errorf("agent received %d unrecognised request types", f.countBad())
	}
}

func TestClientAgainstFakeAgent(t *testing.T) {
	blob := testBlob("ssh-ed25519")
	f, conn := newFakeAgent(t, []Identity{
		{Blob: blob, Comment: "work laptop"},
		{Blob: testBlob("ssh-rsa"), Comment: "old"},
	})
	cl := &Client{c: conn, name: "fake", rbuf: make([]byte, maxAgentReply)}
	defer cl.Close()

	ids, err := cl.Identities()
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}
	if ids[0].Algo != "ssh-ed25519" || ids[0].Comment != "work laptop" {
		t.Errorf("identity 0 = %+v", ids[0])
	}
	if !bytesEqual(ids[0].Blob, blob) {
		t.Errorf("blob round trip mismatch")
	}
	// A reply is reusable: the read buffer must not be corrupted by the
	// first exchange, which is what the message-mode fix was about.
	again, err := cl.Identities()
	if err != nil || len(again) != 2 {
		t.Fatalf("second Identities = %v, %v", again, err)
	}
	if _, err := cl.Sign(blob, []byte("session id")); err == nil {
		t.Fatal("expected the agent to refuse to sign")
	}
	if f.signed != 1 {
		t.Errorf("agent saw %d sign requests, want 1", f.signed)
	}
	if cl.SupportRsaSha2() {
		t.Error("SupportRsaSha2 should be false when the agent rejects the extension")
	}
	if f.countBad() != 0 {
		t.Errorf("agent received %d unknown request types", f.countBad())
	}
}

// TestEmptyVersusRefused keeps the two "no keys" stories apart.  An agent that
// says it holds nothing must not be reported the same way as one that refuses to
// answer, because the fixes they call for are unrelated.
func TestEmptyVersusRefused(t *testing.T) {
	_, conn := newFakeAgent(t, nil)
	cl := &Client{c: conn, name: "empty", rbuf: make([]byte, maxAgentReply)}
	defer cl.Close()
	if _, err := cl.Identities(); !errors.Is(err, ErrNoKeys) {
		t.Errorf("empty agent: Identities = %v, want ErrNoKeys", err)
	}

	f2, conn2 := newFakeAgent(t, []Identity{{Blob: testBlob("ssh-ed25519"), Comment: "present"}})
	f2.refuseIdentities = true
	cl2 := &Client{c: conn2, name: "refusing", rbuf: make([]byte, maxAgentReply)}
	defer cl2.Close()
	if _, err := cl2.Identities(); !errors.Is(err, ErrRefused) {
		t.Errorf("refusing agent: Identities = %v, want ErrRefused", err)
	}
}

// TestExtensionsQuery checks the happy path of extension negotiation, which is
// how rsa-sha2 support is discovered.
func TestExtensionsQuery(t *testing.T) {
	body := []byte{6} // SSH_AGENT_SUCCESS
	body = appendString(body, []byte("query"))
	body = appendString(body, []byte("add-ppk@putty.projects.tartarus.org"))
	body = appendString(body, []byte("rsa-sha2-512-support@openssh.com"))
	f, conn := newFakeAgent(t, nil)
	f.extensionReply = body
	cl := &Client{c: conn, name: "fake", rbuf: make([]byte, maxAgentReply)}
	defer cl.Close()

	exts, err := cl.Extensions()
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	if len(exts) != 3 {
		t.Fatalf("Extensions = %q, want three names", exts)
	}
	if !cl.SupportRsaSha2() {
		t.Error("SupportRsaSha2 = false, want true for an agent advertising rsa-sha2-512-support")
	}
	// The request must be 27, the name "query", and an empty extension data
	// string: four zero bytes on the end.
	req := f.seen()[0]
	if req[0] != 27 {
		t.Fatalf("extension request type = %d, want 27", req[0])
	}
	r := &reader{b: req[1:]}
	name, ok := r.string()
	if !ok || string(name) != "query" {
		t.Fatalf("extension name = %q, want query", name)
	}
	data, ok := r.string()
	if !ok || len(data) != 0 {
		t.Errorf("extension data = %v, want empty", data)
	}
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestClientClosedErrors(t *testing.T) {
	_, conn := newFakeAgent(t, nil)
	cl := &Client{c: conn, name: "fake"}
	if err := cl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := cl.Identities(); !errors.Is(err, ErrClosed) {
		t.Errorf("Identities after Close = %v, want ErrClosed", err)
	}
	if err := cl.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestSignRequestsTheAlgorithmAskedFor pins the flags word on the wire.
//
// An ssh-rsa key can sign three different ways, and which one the agent
// produces is decided solely by this flags word. winsh used to ask for the
// default (SHA-256) no matter which algorithm the userauth packet went on to
// claim, so offering rsa-sha2-512 while holding an rsa-sha2-256 signature made
// servers refuse a perfectly good key with no explanation.
func TestSignRequestsTheAlgorithmAskedFor(t *testing.T) {
	rsa := testBlob("ssh-rsa")
	for _, tc := range []struct {
		ask      string
		wantFlag uint32
	}{
		{"rsa-sha2-512", 4},
		{"rsa-sha2-256", 2},
		{"ssh-rsa", 0},
		{"", 2}, // no preference: the client picks a SHA-2 variant, not SHA-1
	} {
		f, conn := newFakeAgent(t, []Identity{{Blob: rsa, Comment: "rsa"}})
		f.signAlgorithm = tc.ask
		if tc.ask == "" {
			f.signAlgorithm = "rsa-sha2-256"
		}
		cl := &Client{c: conn, name: "fake", rbuf: make([]byte, maxAgentReply)}
		sig, err := cl.SignWithAlgo(rsa, []byte("session id"), tc.ask)
		if err != nil {
			t.Errorf("SignWithAlgo(%q): %v", tc.ask, err)
			cl.Close()
			continue
		}
		if got := signatureAlgo(sig); got != f.signAlgorithm {
			t.Errorf("SignWithAlgo(%q) returned a %s signature", tc.ask, got)
		}
		flags := f.signFlags
		cl.Close()
		if len(flags) != 1 || flags[0] != tc.wantFlag {
			t.Errorf("SignWithAlgo(%q) sent flags %v, want [%d]", tc.ask, flags, tc.wantFlag)
		}
	}

	// An agent that returns a different algorithm from the one requested must
	// be contradicted rather than quietly accepted.
	f, conn := newFakeAgent(t, []Identity{{Blob: rsa, Comment: "rsa"}})
	f.signAlgorithm = "ssh-rsa"
	cl := &Client{c: conn, name: "fake", rbuf: make([]byte, maxAgentReply)}
	defer cl.Close()
	if _, err := cl.SignWithAlgo(rsa, []byte("x"), "rsa-sha2-512"); err == nil {
		t.Error("an rsa-sha2-512 request answered with an ssh-rsa signature was accepted")
	}

	// Asking an ed25519 key for an RSA signature is nonsense and must not be
	// sent at all.
	ed := testBlob("ssh-ed25519")
	f2, conn2 := newFakeAgent(t, []Identity{{Blob: ed, Comment: "ed"}})
	cl2 := &Client{c: conn2, name: "fake", rbuf: make([]byte, maxAgentReply)}
	defer cl2.Close()
	if _, err := cl2.SignWithAlgo(ed, []byte("x"), "rsa-sha2-256"); err == nil {
		t.Error("an ed25519 key was allowed to sign as rsa-sha2-256")
	}
	if len(f2.signFlags) != 0 {
		t.Errorf("refused request still reached the agent: %v", f2.signFlags)
	}
}
