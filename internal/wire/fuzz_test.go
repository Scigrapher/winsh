package wire

import "testing"

func FuzzParse(f *testing.F) {
	var seed Buffer
	seed.Uint64(1, 42)
	seed.AppendBytes(2, []byte("payload"))
	seed.AppendString(3, "text")
	f.Add(seed.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		_, _ = Parse(data)
	})
}
