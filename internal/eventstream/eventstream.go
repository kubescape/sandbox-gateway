// Package eventstream is a minimal AWS event-stream codec for S7: Bedrock
// ConverseStream / InvokeModelWithResponseStream bodies are binary frames, not
// SSE, each with two CRC32s. A processor that rewrites a frame must re-encode it
// with fresh CRCs; one that only reads frames must cope with frames split across
// body chunks.
//
// Frame layout (big endian):
//
//	total_len u32 | headers_len u32 | prelude_crc u32 | headers | payload | message_crc u32
//
// prelude_crc covers the first 8 bytes; message_crc covers everything before it.
// Headers are kept as raw bytes per header, so frames we don't change re-encode
// byte for byte whatever header types they use.
package eventstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	preludeLen = 12
	crcLen     = 4
	minFrame   = preludeLen + crcLen
	// MaxFrame bounds a single frame (AWS's own limit is 16 MiB plus headers).
	MaxFrame = 24 << 20
)

// ErrCRC is returned for a frame whose prelude or message CRC doesn't match.
var ErrCRC = errors.New("eventstream: crc mismatch")

// Header is one header with its raw type byte and raw value bytes (as on the
// wire, after the type byte).
type Header struct {
	Name  string
	Type  byte
	Value []byte
}

// StringHeader builds a type-7 (string) header.
func StringHeader(name, value string) Header {
	v := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(v, uint16(len(value)))
	copy(v[2:], value)
	return Header{Name: name, Type: 7, Value: v}
}

// String returns a type-7 header's value, or "" for other types.
func (h Header) String() string {
	if h.Type != 7 || len(h.Value) < 2 {
		return ""
	}
	return string(h.Value[2:])
}

// Frame is one decoded message.
type Frame struct {
	Headers []Header
	Payload []byte
}

// Get returns the string value of the named header.
func (f Frame) Get(name string) string {
	for _, h := range f.Headers {
		if h.Name == name {
			return h.String()
		}
	}
	return ""
}

// Encode returns the wire bytes of f with fresh CRCs.
func Encode(f Frame) []byte {
	var hb []byte
	for _, h := range f.Headers {
		hb = append(hb, byte(len(h.Name)))
		hb = append(hb, h.Name...)
		hb = append(hb, h.Type)
		hb = append(hb, h.Value...)
	}
	total := preludeLen + len(hb) + len(f.Payload) + crcLen
	b := make([]byte, 0, total)
	b = binary.BigEndian.AppendUint32(b, uint32(total))
	b = binary.BigEndian.AppendUint32(b, uint32(len(hb)))
	b = binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b[:8]))
	b = append(b, hb...)
	b = append(b, f.Payload...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
}

// Decoder turns body chunks into frames, keeping a partial frame between calls.
type Decoder struct {
	buf []byte
}

// Feed adds a chunk and returns the complete frames it finished, each with its
// raw wire bytes.
func (d *Decoder) Feed(chunk []byte) ([]Frame, [][]byte, error) {
	d.buf = append(d.buf, chunk...)
	var frames []Frame
	var raws [][]byte
	for len(d.buf) >= preludeLen {
		total := int(binary.BigEndian.Uint32(d.buf[0:4]))
		if crc32.ChecksumIEEE(d.buf[:8]) != binary.BigEndian.Uint32(d.buf[8:12]) {
			return frames, raws, fmt.Errorf("%w (prelude)", ErrCRC)
		}
		if total < minFrame || total > MaxFrame {
			return frames, raws, fmt.Errorf("eventstream: bad frame length %d", total)
		}
		if len(d.buf) < total {
			break
		}
		raw := d.buf[:total]
		f, err := decode(raw)
		if err != nil {
			return frames, raws, err
		}
		frames = append(frames, f)
		raws = append(raws, append([]byte(nil), raw...))
		d.buf = d.buf[total:]
	}
	return frames, raws, nil
}

// Pending is the number of buffered bytes of an incomplete frame.
func (d *Decoder) Pending() int { return len(d.buf) }

func decode(raw []byte) (Frame, error) {
	total := len(raw)
	if crc32.ChecksumIEEE(raw[:total-crcLen]) != binary.BigEndian.Uint32(raw[total-crcLen:]) {
		return Frame{}, fmt.Errorf("%w (message)", ErrCRC)
	}
	hlen := int(binary.BigEndian.Uint32(raw[4:8]))
	if preludeLen+hlen > total-crcLen {
		return Frame{}, fmt.Errorf("eventstream: headers length %d overruns frame", hlen)
	}
	hb := raw[preludeLen : preludeLen+hlen]
	var f Frame
	for len(hb) > 0 {
		n := int(hb[0])
		if 1+n+1 > len(hb) {
			return Frame{}, errors.New("eventstream: truncated header")
		}
		name := string(hb[1 : 1+n])
		typ := hb[1+n]
		rest := hb[2+n:]
		vlen, err := valueLen(typ, rest)
		if err != nil {
			return Frame{}, err
		}
		f.Headers = append(f.Headers, Header{Name: name, Type: typ, Value: append([]byte(nil), rest[:vlen]...)})
		hb = rest[vlen:]
	}
	f.Payload = append([]byte(nil), raw[preludeLen+hlen:total-crcLen]...)
	return f, nil
}

// valueLen is the wire length of a header value of the given type.
func valueLen(typ byte, b []byte) (int, error) {
	fixed := map[byte]int{0: 0, 1: 0, 2: 1, 3: 2, 4: 4, 5: 8, 8: 8, 9: 16}
	if n, ok := fixed[typ]; ok {
		if n > len(b) {
			return 0, errors.New("eventstream: truncated header value")
		}
		return n, nil
	}
	if typ == 6 || typ == 7 { // bytes, string: u16 length prefix
		if len(b) < 2 {
			return 0, errors.New("eventstream: truncated header value")
		}
		n := 2 + int(binary.BigEndian.Uint16(b))
		if n > len(b) {
			return 0, errors.New("eventstream: truncated header value")
		}
		return n, nil
	}
	return 0, fmt.Errorf("eventstream: unknown header type %d", typ)
}
