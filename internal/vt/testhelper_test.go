package vt

import "winsh/internal/ssp"

// hostMessageWithBytes builds a one-instruction HostMessage; it exists so the
// tests can drive ApplyString without hand-encoding protobuf.
func hostStringForDebug(diff []byte) string {
	hm, err := ssp.ParseHostMessage(diff)
	if err != nil {
		return ""
	}
	var out string
	for _, in := range hm.Instructions {
		if in.Kind == ssp.HostKindBytes {
			out += string(in.Bytes)
		}
	}
	return out
}

func hostMessageWithBytes(b []byte) []byte {
	return (&ssp.HostMessage{Instructions: []ssp.HostInstruction{
		{Kind: ssp.HostKindBytes, Bytes: b},
	}}).Marshal()
}
