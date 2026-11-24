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
	// Dropped marks where the parser dropped an over-long line or an
	// over-size event, in order with the events around it. Such a marker has
	// no name or data. Feed returns markers only when MarkDrops is set.
	Dropped bool
}

// Parser accumulates bytes and returns complete events.
type Parser struct {
	buf      []byte
	name     string
	data     []byte
	haveData bool
	MaxLine  int // lines longer than this are dropped; default 1 MiB
	MaxEvent int // an event whose data lines add up to more than this is dropped; default 4 MiB
	Dropped  int // count of dropped over-long lines and over-size events
	// MarkDrops makes Feed and Close return an Event with Dropped set at each
	// drop, so a caller can tell which events came before it.
	MarkDrops bool
	marked    bool // line() dropped an event; the loop emits the marker
	skipping  bool
	dropping  bool // the event in progress went over MaxEvent
}

// Feed adds a chunk and returns the events it completed.
func (p *Parser) Feed(chunk []byte) []Event { return p.feed(chunk, false) }

// Close ends the stream and returns the events that only the end completes.
// SSE allows a lone CR as a line end, so a CR that Feed held back waiting for a
// possible LF ends a line here; if that line is the blank line, its event is
// dispatched. Each returned event's End is 0: the event ends at the last byte
// fed. An event that never got its blank line is discarded, as the SSE parsing
// rules say, and so is a final line with no line end. The parser is reset.
func (p *Parser) Close() []Event {
	out := p.feed(nil, true)
	p.buf, p.name, p.data, p.haveData = p.buf[:0], "", p.data[:0], false
	p.skipping, p.dropping, p.marked = false, false, false
	return out
}

func (p *Parser) feed(chunk []byte, eof bool) []Event {
	if p.MaxLine == 0 {
		p.MaxLine = 1 << 20
	}
	if p.MaxEvent == 0 {
		p.MaxEvent = 4 << 20
	}
	carried := len(p.buf) // bytes from earlier chunks still in the buffer
	p.buf = append(p.buf, chunk...)
	consumed := 0 // bytes of p.buf (as it was after append) consumed so far
	var out []Event
	for {
		i := bytes.IndexAny(p.buf, "\r\n")
		if i < 0 {
			if len(p.buf) > p.MaxLine {
				end := consumed + len(p.buf) - carried
				p.buf = p.buf[:0]
				if !p.skipping {
					p.drop(&out, end)
				}
				p.skipping = true
			}
			return out
		}
		adv := i + 1
		if p.buf[i] == '\r' {
			if i+1 == len(p.buf) {
				if !eof {
					return out // CR at chunk end: wait to see if LF follows
				}
			} else if p.buf[i+1] == '\n' {
				adv = i + 2
			}
		}
		line := p.buf[:i]
		switch {
		case p.skipping: // the tail of a line already dropped
			p.skipping = false
		case len(line) > p.MaxLine:
			p.drop(&out, consumed+adv-carried)
		default:
			ev, ok := p.line(line)
			if p.marked {
				p.marked = false
				p.drop(&out, consumed+adv-carried)
			}
			if ok {
				ev.End = max(consumed+adv-carried, 0)
				out = append(out, ev)
			}
		}
		consumed += adv
		p.buf = p.buf[adv:]
	}
}

func (p *Parser) line(line []byte) (Event, bool) {
	if len(line) == 0 {
		if p.dropping { // over-size event: end it without dispatching
			p.name, p.data, p.haveData, p.dropping = "", p.data[:0], false, false
			return Event{}, false
		}
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
		if p.dropping {
			break
		}
		// A stream that never sends the blank line would otherwise grow p.data
		// without limit, one in-bounds line at a time.
		if len(p.data)+len(value)+1 > p.MaxEvent {
			p.data, p.dropping, p.marked = p.data[:0], true, true
			break
		}
		if p.haveData {
			p.data = append(p.data, '\n')
		}
		p.data = append(p.data, value...)
		p.haveData = true
	}
	return Event{}, false
}

// drop counts a drop and, with MarkDrops, adds its marker to out. end is the
// offset in the chunk where the drop was noticed.
func (p *Parser) drop(out *[]Event, end int) {
	p.Dropped++
	if p.MarkDrops {
		*out = append(*out, Event{Dropped: true, End: max(end, 0)})
	}
}

// Pending is the number of buffered bytes that do not yet form a complete
// line. A caller cutting a stream at an event boundary forwards everything
// except these bytes.
func (p *Parser) Pending() int { return len(p.buf) }
