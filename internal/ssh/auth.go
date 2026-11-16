package ssh

import (
	"errors"
	"fmt"

	"winsh/internal/keys"
	"winsh/internal/textsafe"
)

// authenticate runs the userauth phase.
//
// Public key material comes from an agent (Pageant or ssh-agent) or from
// ~/.ssh, never from a password file; password and keyboard-interactive are
// offered only when the server requires them and only through the caller's
// Prompt callback.
// requestService sends SSH_MSG_SERVICE_REQUEST and waits for the accept.
func (c *Client) requestService(name string) error {
	var o builder
	o.byte_(msgServiceRequest)
	o.str([]byte(name))
	if err := c.writePacket(o.b); err != nil {
		return err
	}
	c.log("requested service %q", name)
	p, err := c.expect(msgServiceAccept)
	if err != nil {
		return err
	}
	m := &msg{b: p[1:]}
	got, ok := m.str()
	if !ok {
		return m.err
	}
	if string(got) != name {
		return fmt.Errorf("ssh: server accepted service %q, not %q", got, name)
	}
	return nil
}

func (c *Client) authenticate() error {
	// RFC 4253 requires a service to be requested before any protocol that
	// belongs to it may be used, so authentication begins by asking for
	// "ssh-userauth" and waiting for the accept.  Skipping it looks harmless
	// because a DISCONNECT is an error either way, but OpenSSH will not even
	// look at a USERAUTH_REQUEST that arrives with no service running -- and it
	// hangs up rather than explaining itself.
	if err := c.requestService("ssh-userauth"); err != nil {
		return err
	}

	none := func() ([]byte, error) {
		var o builder
		o.byte_(msgUserAuthRequest)
		o.str([]byte(c.cfg.User))
		o.str([]byte("ssh-connection"))
		o.str([]byte("none"))
		if err := c.writePacket(o.b); err != nil {
			return nil, err
		}
		c.log("sent USERAUTH_REQUEST (none)")
		return c.expect(msgUserAuthSuccess, msgUserAuthFailure, msgUserAuthBanner, msgUserAuthInfoRequest)
	}

	p, err := none()
	if err != nil {
		return err
	}
	for p[0] == msgUserAuthBanner || p[0] == msgUserAuthInfoRequest {
		if p[0] == msgUserAuthBanner {
			m := &msg{b: p[1:]}
			msgText, _ := m.str()
			if c.cfg.Banner != nil {
				c.cfg.Banner(textsafe.Terminal(string(msgText), 4096))
			}
		} else {
			// The server jumped straight into keyboard-interactive.
			return c.keyboardInteractive()
		}
		p, err = c.expect(msgUserAuthSuccess, msgUserAuthFailure, msgUserAuthBanner, msgUserAuthInfoRequest)
		if err != nil {
			return err
		}
	}
	if p[0] == msgUserAuthSuccess {
		c.log("authenticated with no credentials")
		return nil
	}
	if p[0] != msgUserAuthFailure {
		return fmt.Errorf("%w: unexpected userauth reply %d", ErrUnsupported, p[0])
	}
	m := &msg{b: p[1:]}
	allowed, ok := m.nameList()
	if !ok {
		return m.err
	}
	c.log("server allows: %v", allowed)

	hasPublic := false
	for _, a := range allowed {
		if a == "publickey" {
			hasPublic = true
		}
	}
	if hasPublic {
		if err := c.authPublickey(); err == nil {
			return nil
		} else if !errors.Is(err, errNoPubkeys) {
			c.log("publickey auth failed: %v", err)
		}
	}
	for _, a := range allowed {
		if c.cfg.Prompt == nil {
			break
		}
		switch a {
		case "password":
			if err := c.authPassword(); err == nil {
				return nil
			} else {
				c.log("password auth failed: %v", err)
			}
		case "keyboard-interactive":
			if err := c.keyboardInteractive(); err == nil {
				return nil
			} else {
				c.log("keyboard-interactive failed: %v", err)
			}
		}
	}
	return ErrNoAuthMethods
}

var errNoPubkeys = errors.New("ssh: no usable private keys")

// authPublickey offers each key in turn, signing the canonical
// SSH_MSG_USERAUTH_REQUEST body for it.
func (c *Client) authPublickey() error {
	if len(c.cfg.Signers) == 0 {
		return errNoPubkeys
	}
	any := false
	for _, s := range c.cfg.Signers {
		for _, algo := range s.AllowedAlgos() {
			if !hostKeyAlgoUsable(algo) {
				continue
			}
			any = true
			pub := s.Pub()

			var body builder
			body.byte_(msgUserAuthRequest)
			body.str([]byte(c.cfg.User))
			body.str([]byte("ssh-connection"))
			body.str([]byte("publickey"))
			body.boolv(true)
			body.str([]byte(algo))
			body.str(pub.Blob)
			// RFC 4252 section 7: the signed data is the session id
			// followed by the whole request as far as the public key
			// blob, INCLUDING the SSH_MSG_USERAUTH_REQUEST byte. Dropping
			// that one byte produces a signature that is well formed,
			// correctly wrapped, and silently refused.
			sigMsg := append([]byte(nil), body.b...)
			// The signed blob prefixes the session id.
			var signed builder
			signed.str(c.sessionID)
			signed.raw(sigMsg)

			sig, err := s.Sign(algo, signed.b)
			if err != nil {
				c.log("sign with %s failed: %v", s.Source(), err)
				continue
			}
			var full builder
			full.byte_(msgUserAuthRequest)
			full.str([]byte(c.cfg.User))
			full.str([]byte("ssh-connection"))
			full.str([]byte("publickey"))
			full.boolv(true)
			full.str([]byte(algo))
			full.str(pub.Blob)
			full.str(sig)
			if err := c.writePacket(full.b); err != nil {
				return err
			}
			p, err := c.expect(msgUserAuthSuccess, msgUserAuthFailure, msgUserAuthBanner)
			if err != nil {
				return err
			}
			if p[0] == msgUserAuthSuccess {
				c.log("authenticated with %s (%s)", algo, s.Source())
				return nil
			}
			c.log("%s rejected by server", s.Source())
		}
	}
	if !any {
		return errNoPubkeys
	}
	return ErrNoAuthMethods
}

func hostKeyAlgoUsable(algo string) bool {
	switch algo {
	case "ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256",
		"sk-ssh-ed25519@openssh.com":
		return true
	}
	return false
}

func (c *Client) authPassword() error {
	for attempt := 0; attempt < 3; attempt++ {
		label := "password"
		if c.cfg.User != "" {
			label = fmt.Sprintf("%s@%s's password", c.cfg.User, c.cfg.host())
		}
		secret, err := c.cfg.Prompt(label, false)
		if err != nil {
			return err
		}
		var o builder
		o.byte_(msgUserAuthRequest)
		o.str([]byte(c.cfg.User))
		o.str([]byte("ssh-connection"))
		o.str([]byte("password"))
		o.boolv(false)
		o.str([]byte(secret))
		if err := c.writePacket(o.b); err != nil {
			return err
		}
		p, err := c.expect(msgUserAuthSuccess, msgUserAuthFailure, msgUserAuthBanner)
		if err != nil {
			return err
		}
		if p[0] == msgUserAuthSuccess {
			return nil
		}
	}
	return ErrNoAuthMethods
}

func (c *Client) keyboardInteractive() error {
	if c.cfg.Prompt == nil {
		return ErrNoAuthMethods
	}
	var o builder
	o.byte_(msgUserAuthRequest)
	o.str([]byte(c.cfg.User))
	o.str([]byte("ssh-connection"))
	o.str([]byte("keyboard-interactive"))
	o.str(nil) // language tag
	o.str(nil) // submethods
	if err := c.writePacket(o.b); err != nil {
		return err
	}
	for {
		p, err := c.expect(msgUserAuthSuccess, msgUserAuthFailure, msgUserAuthInfoRequest, msgUserAuthBanner)
		if err != nil {
			return err
		}
		switch p[0] {
		case msgUserAuthSuccess:
			return nil
		case msgUserAuthBanner:
			continue
		case msgUserAuthFailure:
			return ErrNoAuthMethods
		}
		m := &msg{b: p[1:]}
		if _, ok := m.str(); !ok { // name
			return m.err
		}
		if _, ok := m.str(); !ok { // instruction
			return m.err
		}
		if _, ok := m.str(); !ok { // language tag
			return m.err
		}
		n, ok := m.uint32()
		if !ok || n > 32 {
			return errors.New("ssh: implausible prompt count")
		}
		var resp builder
		resp.byte_(msgUserAuthInfoResponse)
		for i := uint32(0); i < n; i++ {
			prompt, ok := m.str()
			if !ok {
				return m.err
			}
			echo, ok := m.boolv()
			if !ok {
				return m.err
			}
			answer, err := c.cfg.Prompt(string(prompt), echo)
			if err != nil {
				return err
			}
			resp.str([]byte(answer))
		}
		if err := c.writePacket(resp.b); err != nil {
			return err
		}
	}
}

// verifyHostKey enforces host key authentication, the one step that actually
// protects the session from a man in the middle.
func (c *Client) verifyHostKey(pub keys.PubKey, exchangeHash, sig []byte) error {
	if err := keys.VerifyHostKey(pub, exchangeHash, sig, c.cfg.AllowSHA1HostKey); err != nil {
		return err
	}
	matches, err := lookupKnownHost(c.cfg.KnownHostFiles, c.cfg.host(), c.cfg.Port)
	if err != nil {
		return err
	}
	found, err := matches.check(pub)
	if found {
		if err == nil {
			c.log("host key matched known_hosts")
		}
		return err
	}
	displayName := knownHostName(c.cfg.host(), c.cfg.Port)
	if c.cfg.HostKeyCallback != nil {
		if c.cfg.HostKeyCallback(displayName, pub) {
			c.log("host key accepted by callback")
			return nil
		}
		return fmt.Errorf("%w: %s %s", ErrHostKeyUnknown, displayName, pub.Fingerprint())
	}
	return fmt.Errorf("%w: %s\n  %s %s\nAdd it to %v or run once with a host key confirmation prompt",
		ErrHostKeyUnknown, displayName, pub.Algo, pub.Fingerprint(), c.cfg.KnownHostFiles)
}
