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

// Decoder holds the state of a partial frame between chunks. It never buffers
// a payload: bytes are unmasked and counted as they arrive, and only the first
// MaxMessage bytes of a message are kept. Memory use is bounded by MaxMessage
// plus one frame header, whatever length a frame declares.
type Decoder struct {
	MaxMessage int // payload bytes kept per message; default 64 KiB

	hdr     []byte // header bytes of the frame being read, at most 14
	inFrame bool   // header parsed, payload in progress
	remain  uint64 // payload bytes of the current frame still to come
	frameN  int    // declared payload length of the current frame
	fin     bool
	op      byte
	masked  bool
	key     [4]byte
	kpos    int    // position in the masking key
	ctl     []byte // payload of the control frame in progress, at most 125 bytes

	msgOp  byte
	msg    []byte
	msgLen int
	inMsg  bool
	dead   bool
}

// ErrProtocol is returned for frames that break RFC 6455.
var ErrProtocol = errors.New("wsframe: protocol error")

// maxControl is the largest payload RFC 6455 allows on a control frame.
const maxControl = 125

// Dead reports whether the decoder hit a protocol error. A dead decoder drops
// all further input: after a bad frame the stream cannot be resynchronised.
func (d *Decoder) Dead() bool { return d.dead }

// Buffered is the number of bytes the decoder is holding.
func (d *Decoder) Buffered() int { return len(d.hdr) + len(d.ctl) + len(d.msg) }

// Feed adds a chunk and returns the messages it completed. After it returns
// ErrProtocol once, every later call returns ErrProtocol and keeps nothing.
func (d *Decoder) Feed(chunk []byte) ([]Message, error) {
	if d.dead {
		return nil, ErrProtocol
	}
	if d.MaxMessage == 0 {
		d.MaxMessage = 64 << 10
	}
	var out []Message
	for len(chunk) > 0 {
		if !d.inFrame {
			d.hdr = append(d.hdr, chunk[0])
			chunk = chunk[1:]
			ready, err := d.startFrame()
			if err != nil {
				return out, d.fail()
			}
			if !ready {
				continue
			}
			if d.remain == 0 {
				out = d.endFrame(out)
			}
			continue
		}
		n := len(chunk)
		if uint64(n) > d.remain {
			n = int(d.remain)
		}
		d.take(chunk[:n])
		chunk = chunk[n:]
		d.remain -= uint64(n)
		if d.remain == 0 {
			out = d.endFrame(out)
		}
	}
	return out, nil
}

func (d *Decoder) fail() error {
	d.dead = true
	d.hdr, d.ctl, d.msg = nil, nil, nil
	return ErrProtocol
}

// startFrame parses d.hdr once it holds a whole header. It reports false while
// more header bytes are needed.
func (d *Decoder) startFrame() (bool, error) {
	if len(d.hdr) < 2 {
		return false, nil
	}
	masked := d.hdr[1]&0x80 != 0
	short := d.hdr[1] & 0x7F
	h := 2
	switch short {
	case 126:
		h = 4
	case 127:
		h = 10
	}
	lenEnd := h
	if masked {
		h += 4
	}
	if len(d.hdr) < h {
		return false, nil
	}
	n := uint64(short)
	switch short {
	case 126:
		n = uint64(binary.BigEndian.Uint16(d.hdr[2:4]))
	case 127:
		n = binary.BigEndian.Uint64(d.hdr[2:10])
		if n > 1<<40 {
			return false, ErrProtocol
		}
	}
	d.fin = d.hdr[0]&0x80 != 0
	d.op = d.hdr[0] & 0x0F
	d.masked = masked
	if masked {
		copy(d.key[:], d.hdr[lenEnd:h])
	}
	d.kpos = 0
	d.hdr = d.hdr[:0]
	if d.op >= 0x8 { // control frames are never fragmented and stay small
		if n > maxControl || !d.fin {
			return false, ErrProtocol
		}
		d.ctl = d.ctl[:0]
	} else {
		if d.op != OpContinuation {
			if d.inMsg {
				return false, ErrProtocol
			}
			d.inMsg, d.msgOp, d.msg, d.msgLen = true, d.op, d.msg[:0], 0
		} else if !d.inMsg {
			return false, ErrProtocol
		}
		d.msgLen += int(n)
	}
	d.inFrame, d.remain, d.frameN = true, n, int(n)
	return true, nil
}

// take consumes payload bytes of the current frame, keeping only what fits.
func (d *Decoder) take(b []byte) {
	keep := len(b)
	if d.op < 0x8 {
		if room := d.MaxMessage - len(d.msg); room < keep {
			keep = max(room, 0)
		}
	}
	dst := &d.msg
	if d.op >= 0x8 {
		dst = &d.ctl
	}
	for i := 0; i < keep; i++ {
		c := b[i]
		if d.masked {
			c ^= d.key[(d.kpos+i)%4]
		}
		*dst = append(*dst, c)
	}
	d.kpos = (d.kpos + len(b)) % 4
}

// endFrame closes the current frame and emits a message when one completed.
func (d *Decoder) endFrame(out []Message) []Message {
	d.inFrame = false
	if d.op >= 0x8 {
		return append(out, Message{Opcode: d.op, Payload: append([]byte(nil), d.ctl...), Len: d.frameN})
	}
	if d.fin {
		out = append(out, Message{Opcode: d.msgOp, Payload: append([]byte(nil), d.msg...), Len: d.msgLen, Truncated: d.msgLen > len(d.msg)})
		d.inMsg = false
	}
	return out
}
