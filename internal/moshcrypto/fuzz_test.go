package moshcrypto

import "testing"

func FuzzSessionDecrypt(f *testing.F) {
	previous := UseSystemCrypto(false)
	defer UseSystemCrypto(previous)

	session, err := NewSession(Key{})
	if err != nil {
		f.Fatal(err)
	}
	valid, err := session.Encrypt(1, []byte("hello"))
	session.Destroy()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, ReceiveMTU))
	f.Add(append(append([]byte(nil), valid...), 0xff))

	f.Fuzz(func(t *testing.T, datagram []byte) {
		if len(datagram) > ReceiveMTU {
			return
		}
		session, err := NewSession(Key{})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Destroy()
		_, _, _ = session.Decrypt(datagram)
	})
}
