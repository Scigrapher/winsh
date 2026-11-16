package agent

import (
	"encoding/binary"
	"testing"
)

func FuzzIdentityReplyParsing(f *testing.F) {
	blob := []byte{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9'}
	seed := []byte{identitiesAnswer}
	seed = append(seed, make([]byte, 4)...)
	binary.BigEndian.PutUint32(seed[1:5], 1)
	seed = appendString(seed, blob)
	seed = appendString(seed, []byte("fuzz comment"))
	f.Add(seed)
	f.Add([]byte{agentFailure})
	f.Add([]byte{identitiesAnswer, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{identitiesAnswer, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		_, _ = parseIdentitiesReply(data, "fuzz-agent")
		_ = signatureAlgo(data)
	})
}

func FuzzAgentReader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 'x'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		r := &reader{b: data}
		for i := 0; i < 4096 && !r.done(); i++ {
			switch i % 3 {
			case 0:
				_, _ = r.uint32()
			case 1:
				_, _ = r.string()
			case 2:
				_, _ = r.bytes(16)
			}
		}
	})
}
