// Package wsframe decodes RFC 6455 WebSocket frames incrementally, as body
// chunks arrive from Envoy after an upgrade (S5: ext_proc does receive them).
// Client-to-server frames are masked; the decoder unmasks them. Fragmented
// messages (FIN=0 then continuation frames) are reassembled up to MaxMessage.
package wsframe

import (
	"encoding/binary"
	"errors"
)

// Opcodes.
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

// Message is one complete message (or control frame).
type Message struct {
	Opcode    byte
	Payload   []byte // up to MaxMessage bytes
	Len       int    // full length, even when Payload was capped
	Truncated bool
}

// Decoder holds a partial frame between chunks.
type Decoder struct {
	MaxMessage int // payload bytes kept per message; default 64 KiB
	buf        []byte
	msgOp      byte
	msg        []byte
	msgLen     int
	inMsg      bool
}

// ErrProtocol is returned for frames that break RFC 6455.
var ErrProtocol = errors.New("wsframe: protocol error")

// Feed adds a chunk and returns the messages it completed.
func (d *Decoder) Feed(chunk []byte) ([]Message, error) {
	if d.MaxMessage == 0 {
		d.MaxMessage = 64 << 10
	}
	d.buf = append(d.buf, chunk...)
	var out []Message
	for {
		if len(d.buf) < 2 {
			return out, nil
		}
		fin := d.buf[0]&0x80 != 0
		op := d.buf[0] & 0x0F
		masked := d.buf[1]&0x80 != 0
		n := int(d.buf[1] & 0x7F)
		h := 2
		switch n {
		case 126:
			if len(d.buf) < 4 {
				return out, nil
			}
			n, h = int(binary.BigEndian.Uint16(d.buf[2:4])), 4
		case 127:
			if len(d.buf) < 10 {
				return out, nil
			}
			n64 := binary.BigEndian.Uint64(d.buf[2:10])
			if n64 > 1<<40 {
				return out, ErrProtocol
			}
			n, h = int(n64), 10
		}
		var key []byte
		if masked {
			if len(d.buf) < h+4 {
				return out, nil
			}
			key, h = d.buf[h:h+4], h+4
		}
		if len(d.buf) < h+n {
			return out, nil // wait for the rest of the payload
		}
		payload := d.buf[h : h+n]
		if masked {
			p := make([]byte, n)
			for i := range payload {
				p[i] = payload[i] ^ key[i%4]
			}
			payload = p
		}
		if op >= 0x8 { // control frames are never fragmented
			out = append(out, Message{Opcode: op, Payload: append([]byte(nil), payload...), Len: n})
		} else {
			if op != OpContinuation {
				if d.inMsg {
					return out, ErrProtocol
				}
				d.inMsg, d.msgOp, d.msg, d.msgLen = true, op, d.msg[:0], 0
			} else if !d.inMsg {
				return out, ErrProtocol
			}
			d.msgLen += n
			if room := d.MaxMessage - len(d.msg); room > 0 {
				if len(payload) > room {
					payload = payload[:room]
				}
				d.msg = append(d.msg, payload...)
			}
			if fin {
				out = append(out, Message{Opcode: d.msgOp, Payload: append([]byte(nil), d.msg...), Len: d.msgLen, Truncated: d.msgLen > len(d.msg)})
				d.inMsg = false
			}
		}
		d.buf = d.buf[h+n:]
	}
}
