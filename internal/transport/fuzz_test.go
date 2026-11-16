package transport

import (
	"bytes"
	"testing"

	"winsh/internal/moshcrypto"
)

func FuzzFragmentAndInflate(f *testing.F) {
	valid := (&Fragment{ID: 1, Num: 0, Final: true, Contents: []byte("payload")}).Marshal()
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1, 0x80, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		frag, err := ParseFragment(data)
		if err == nil {
			var assembly Assembly
			_, _ = assembly.Add(frag)
		}
		_, _ = Inflate(data, 64*1024)
	})
}

func FuzzPacketSealOpen(f *testing.F) {
	previous := moshcrypto.UseSystemCrypto(false)
	defer moshcrypto.UseSystemCrypto(previous)

	f.Add([]byte{})
	f.Add([]byte("payload"))
	f.Add([]byte{0, 1, 2, 3, 4, 5})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 16*1024 {
			return
		}
		session, err := moshcrypto.NewSession(moshcrypto.Key{})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Destroy()
		p := &Packet{
			Seq:            1,
			Direction:      ToClient,
			Timestamp:      1,
			TimestampReply: NoTimestamp,
			Payload:        payload,
		}
		wire, err := p.Seal(session)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := OpenPacket(session, wire)
		if err != nil {
			t.Fatal(err)
		}
		if opened.Seq != p.Seq || opened.Direction != p.Direction ||
			opened.Timestamp != p.Timestamp || opened.TimestampReply != p.TimestampReply ||
			!bytes.Equal(opened.Payload, payload) {
			t.Fatal("packet round trip mismatch")
		}
	})
}
