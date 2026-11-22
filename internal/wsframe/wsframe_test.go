package wsframe

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// frame builds one frame; key != nil masks it (client to server).
func frame(fin bool, op byte, payload []byte, key []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	b := []byte{b0}
	m := byte(0)
	if key != nil {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		b = append(b, m|byte(n))
	case n < 1<<16:
		b = append(b, m|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, m|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if key != nil {
		b = append(b, key...)
		for i, c := range payload {
			b = append(b, c^key[i%4])
		}
		return b
	}
	return append(b, payload...)
}

var key = []byte{0x12, 0x34, 0x56, 0x78}

func stream() []byte {
	var s []byte
	s = append(s, frame(true, OpText, []byte(`{"jsonrpc":"2.0","method":"tools/call"}`), key)...)
	s = append(s, frame(false, OpText, []byte("frag-1 "), key)...)
	s = append(s, frame(true, OpPing, []byte("p"), key)...) // control frame between fragments
	s = append(s, frame(true, OpContinuation, []byte("frag-2"), key)...)
	s = append(s, frame(true, OpBinary, bytes.Repeat([]byte{7}, 300), nil)...) // 16-bit length, unmasked
	s = append(s, frame(true, OpClose, []byte{0x03, 0xE8}, key)...)
	return s
}

func check(t *testing.T, got []Message) {
	t.Helper()
	want := []struct {
		op  byte
		txt string
		n   int
	}{{OpText, `{"jsonrpc":"2.0","method":"tools/call"}`, 39}, {OpPing, "p", 1}, {OpText, "frag-1 frag-2", 13}, {OpBinary, "", 300}, {OpClose, "", 2}}
	if len(got) != len(want) {
		t.Fatalf("got %d messages: %+v", len(got), got)
	}
	for i, w := range want {
		if got[i].Opcode != w.op || got[i].Len != w.n || (w.txt != "" && string(got[i].Payload) != w.txt) {
			t.Fatalf("message %d: %+v, want %+v", i, got[i], w)
		}
	}
}

func TestDecodeWhole(t *testing.T) {
	var d Decoder
	got, err := d.Feed(stream())
	if err != nil {
		t.Fatal(err)
	}
	check(t, got)
}

func TestEverySplitPoint(t *testing.T) {
	s := stream()
	for i := 0; i <= len(s); i++ {
		var d Decoder
		a, err := d.Feed(s[:i])
		if err != nil {
			t.Fatal(err)
		}
		b, err := d.Feed(s[i:])
		if err != nil {
			t.Fatal(err)
		}
		check(t, append(a, b...))
	}
}

func TestCapAndProtocolErrors(t *testing.T) {
	d := Decoder{MaxMessage: 10}
	got, _ := d.Feed(frame(true, OpText, bytes.Repeat([]byte("x"), 100), key))
	if len(got) != 1 || len(got[0].Payload) != 10 || got[0].Len != 100 || !got[0].Truncated {
		t.Fatalf("cap: %+v", got)
	}
	var e Decoder
	if _, err := e.Feed(frame(true, OpContinuation, []byte("x"), nil)); err == nil {
		t.Fatal("continuation without a start: no error")
	}
}
