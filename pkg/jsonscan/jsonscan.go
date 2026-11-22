// Package jsonscan reads string fields from the top level of a JSON object
// without holding the document. A request body can be tens of megabytes (an
// inline image, a long transcript) while the fields a caller wants, such as
// "model", are a few bytes; this scanner reads the body once in constant memory.
package jsonscan

import (
	"io"
	"unicode/utf8"
)

const readBuf = 32 << 10

// Fields reads a JSON object from r and returns the string values of the named
// top-level keys. It reads r to the end, keeps no more than maxValue bytes per
// value, and never holds the document.
//
// A key that is absent, whose value is not a string, or whose value is longer
// than maxValue is left out of the result. When a key repeats, the last
// occurrence decides, as it does in most JSON decoders. A document that is not
// an object yields no fields and no error. A document that ends early returns
// io.ErrUnexpectedEOF along with the fields read up to that point.
//
// Fields checks structure only as far as it needs to find the keys. It is not a
// validator.
func Fields(r io.Reader, maxValue int, keys ...string) (map[string]string, error) {
	s := scanner{want: make(map[string]bool, len(keys)), max: maxValue, out: map[string]string{}}
	for _, k := range keys {
		s.want[k] = true
		s.maxKey = max(s.maxKey, len(k))
	}
	buf := make([]byte, readBuf)
	for {
		n, err := r.Read(buf)
		for _, c := range buf[:n] {
			s.step(c)
		}
		if err == io.EOF {
			if s.started && !s.done {
				return s.out, io.ErrUnexpectedEOF
			}
			return s.out, nil
		}
		if err != nil {
			return s.out, err
		}
	}
}

const (
	capNone = iota
	capKey
	capValue
)

type scanner struct {
	want   map[string]bool
	max    int
	maxKey int
	out    map[string]string

	started, notObject, done bool
	depth                    int
	expectKey                bool   // at depth 1: the next string is a key
	key                      string // the wanted key whose value comes next; "" otherwise
	valuePending             bool   // at depth 1: a ':' was read and its value has not started

	inStr, esc bool
	capture    int
	limit      int
	over       bool // the string being captured went over its limit
	buf        []byte
	uni        int  // hex digits of a \u escape still to read
	uniVal     rune // the escape read so far
	hi         rune // a high surrogate waiting for its low half
}

func (s *scanner) step(c byte) {
	if s.notObject || s.done {
		return
	}
	if !s.started {
		switch c {
		case ' ', '\t', '\n', '\r':
		case '{':
			s.started, s.depth, s.expectKey = true, 1, true
		default:
			s.notObject = true
		}
		return
	}
	if s.inStr {
		s.stringByte(c)
		return
	}
	switch c {
	case ' ', '\t', '\n', '\r':
	case '"':
		s.inStr, s.buf, s.over, s.capture = true, s.buf[:0], false, capNone
		if s.depth != 1 {
			return
		}
		switch {
		case s.expectKey:
			s.capture, s.limit = capKey, s.maxKey
		case s.valuePending:
			s.valuePending = false
			if s.key != "" {
				delete(s.out, s.key)
				s.capture, s.limit = capValue, s.max
			}
		}
	case ':':
		if s.depth == 1 {
			s.valuePending = true
		}
	case ',':
		if s.depth == 1 {
			s.expectKey, s.key, s.valuePending = true, "", false
		}
	case '{', '[':
		s.otherValue()
		s.depth++
	case '}', ']':
		s.depth--
		if s.depth == 0 {
			s.done = true
		}
	default: // a number, true, false or null
		s.otherValue()
	}
}

// otherValue notes that the value of the current top-level key is not a string.
func (s *scanner) otherValue() {
	if s.depth == 1 && s.valuePending {
		s.valuePending = false
		if s.key != "" {
			delete(s.out, s.key)
		}
	}
}

func (s *scanner) stringByte(c byte) {
	if s.capture == capNone {
		// Not kept: only the closing quote matters, so skip escaped bytes whole.
		switch {
		case s.esc:
			s.esc = false
		case c == '\\':
			s.esc = true
		case c == '"':
			s.inStr = false
		}
		return
	}
	switch {
	case s.uni > 0:
		s.uniVal = s.uniVal<<4 | hexVal(c)
		if s.uni--; s.uni == 0 {
			s.escapedRune(s.uniVal)
		}
	case s.esc:
		s.esc = false
		switch c {
		case 'u':
			s.uni, s.uniVal = 4, 0
		case 'n':
			s.put('\n')
		case 't':
			s.put('\t')
		case 'r':
			s.put('\r')
		case 'b':
			s.put('\b')
		case 'f':
			s.put('\f')
		default: // '"', '\\', '/'
			s.put(c)
		}
	case c == '\\':
		s.esc = true
	case c == '"':
		s.flushHi()
		s.endString()
	default:
		s.put(c)
	}
}

func (s *scanner) endString() {
	s.inStr = false
	switch s.capture {
	case capKey:
		s.expectKey, s.key = false, ""
		if !s.over && s.want[string(s.buf)] {
			s.key = string(s.buf)
		}
	case capValue:
		if !s.over {
			s.out[s.key] = string(s.buf)
		}
	}
	s.capture = capNone
}

// put appends one literal byte of the string being captured.
func (s *scanner) put(c byte) {
	s.flushHi()
	if len(s.buf) >= s.limit {
		s.over = true
		return
	}
	s.buf = append(s.buf, c)
}

func (s *scanner) putRune(r rune) {
	if len(s.buf)+utf8.RuneLen(r) > s.limit {
		s.over = true
		return
	}
	s.buf = utf8.AppendRune(s.buf, r)
}

// escapedRune takes the value of one \uXXXX escape and joins surrogate pairs.
func (s *scanner) escapedRune(r rune) {
	switch {
	case r >= 0xD800 && r < 0xDC00:
		s.flushHi()
		s.hi = r
	case r >= 0xDC00 && r < 0xE000:
		if s.hi == 0 {
			s.putRune(utf8.RuneError)
			return
		}
		r = 0x10000 + (s.hi-0xD800)<<10 + (r - 0xDC00)
		s.hi = 0
		s.putRune(r)
	default:
		s.flushHi()
		s.putRune(r)
	}
}

// flushHi writes the replacement character for a high surrogate that was not
// followed by its low half.
func (s *scanner) flushHi() {
	if s.hi != 0 {
		s.hi = 0
		s.putRune(utf8.RuneError)
	}
}

func hexVal(c byte) rune {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0')
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10
	}
	return 0
}
