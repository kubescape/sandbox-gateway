// Package sse parses a Server-Sent Events stream incrementally, as body chunks
// arrive from Envoy. Chunk boundaries fall anywhere: inside a line, inside a
// CRLF pair, or between events.
package sse

import "bytes"

// Event is one dispatched SSE event.
type Event struct {
	Name string // the "event:" field; empty means "message"
	Data string // "data:" lines joined with "\n"
	// End is the offset in the chunk passed to the Feed call that returned this
	// event, just past the blank line that ended it. Forwarding chunk[:End]
	// forwards the stream up to and including this event and nothing after it.
	End int
}

// Parser accumulates bytes and returns complete events.
type Parser struct {
	buf      []byte
	name     string
	data     []byte
	haveData bool
	MaxLine  int // lines longer than this are dropped; default 1 MiB
	Dropped  int // count of dropped over-long lines
	skipping bool
}

// Feed adds a chunk and returns the events it completed.
func (p *Parser) Feed(chunk []byte) []Event {
	if p.MaxLine == 0 {
		p.MaxLine = 1 << 20
	}
	carried := len(p.buf) // bytes from earlier chunks still in the buffer
	p.buf = append(p.buf, chunk...)
	consumed := 0 // bytes of p.buf (as it was after append) consumed so far
	var out []Event
	for {
		i := bytes.IndexAny(p.buf, "\r\n")
		if i < 0 {
			if len(p.buf) > p.MaxLine {
				consumed += len(p.buf)
				p.buf = p.buf[:0]
				if !p.skipping {
					p.Dropped++
				}
				p.skipping = true
			}
			return out
		}
		adv := i + 1
		if p.buf[i] == '\r' {
			if i+1 == len(p.buf) {
				return out // CR at chunk end: wait to see if LF follows
			}
			if p.buf[i+1] == '\n' {
				adv = i + 2
			}
		}
		line := p.buf[:i]
		switch {
		case p.skipping: // the tail of a line already dropped
			p.skipping = false
		case len(line) > p.MaxLine:
			p.Dropped++
		default:
			if ev, ok := p.line(line); ok {
				ev.End = consumed + adv - carried
				if ev.End < 0 {
					ev.End = 0
				}
				out = append(out, ev)
			}
		}
		consumed += adv
		p.buf = p.buf[adv:]
	}
}

func (p *Parser) line(line []byte) (Event, bool) {
	if len(line) == 0 {
		if !p.haveData && p.name == "" {
			return Event{}, false
		}
		ev := Event{Name: p.name, Data: string(p.data)}
		p.name, p.data, p.haveData = "", p.data[:0], false
		return ev, true
	}
	if line[0] == ':' {
		return Event{}, false // comment / keep-alive
	}
	field, value := line, []byte(nil)
	if c := bytes.IndexByte(line, ':'); c >= 0 {
		field, value = line[:c], line[c+1:]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
	}
	switch string(field) {
	case "event":
		p.name = string(value)
	case "data":
		if p.haveData {
			p.data = append(p.data, '\n')
		}
		p.data = append(p.data, value...)
		p.haveData = true
	}
	return Event{}, false
}

// Pending is the number of buffered bytes that do not yet form a complete
// line. A caller cutting a stream at an event boundary forwards everything
// except these bytes.
func (p *Parser) Pending() int { return len(p.buf) }
