package ssp

import "testing"

func FuzzParseMessages(f *testing.F) {
	inst := &Instruction{
		ProtocolVersion: ProtocolVersion, HasProtocol: true,
		OldNum: 1, HasOldNum: true, NewNum: 2, HasNewNum: true,
		AckNum: 1, HasAckNum: true, Diff: []byte("diff"), HasDiff: true,
	}
	f.Add(inst.Marshal())

	user := (&UserMessage{Events: []UserEvent{
		{Byte: 'a'}, {IsResize: true, Width: 120, Height: 40},
	}}).Marshal()
	f.Add(user)

	host := (&HostMessage{Instructions: []HostInstruction{
		{Kind: HostKindBytes, Bytes: []byte("\x1b[2Jhello")},
		{Kind: HostKindResize, Width: 80, Height: 24},
		{Kind: HostKindEcho, EchoAckNum: 7},
	}}).Marshal()
	f.Add(host)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		_, _ = ParseInstruction(data)
		_, _ = ParseUserMessage(data)
		_, _ = ParseHostMessage(data)
	})
}
