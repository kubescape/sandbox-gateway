package sse

import (
	"bytes"
	"reflect"
	"testing"
)

const stream = "event: message_start\r\ndata: {\"type\":\"message_start\"}\r\n\r\n" +
	": ping\n\n" +
	"event: content_block_delta\ndata: {\"a\":1}\ndata: {\"b\":2}\n\n" +
	"event: message_stop\ndata: {}\n\n"

var want = []Event{
	{Name: "message_start", Data: `{"type":"message_start"}`},
	{Name: "content_block_delta", Data: "{\"a\":1}\n{\"b\":2}"},
	{Name: "message_stop", Data: "{}"},
}

func stripEnd(evs []Event) []Event {
	out := make([]Event, len(evs))
	for i, e := range evs {
		e.End = 0
		out[i] = e
	}
	return out
}

func TestWholeStream(t *testing.T) {
	var p Parser
	if got := stripEnd(p.Feed([]byte(stream))); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

// End marks where each event stops in the chunk, so a caller can cut after any event.
func TestEventEndOffsets(t *testing.T) {
	var p Parser
	evs := p.Feed([]byte(stream))
	for i, e := range evs {
		var q Parser
		got := stripEnd(q.Feed([]byte(stream[:e.End])))
		if !reflect.DeepEqual(got, want[:i+1]) {
			t.Fatalf("cut after event %d (End=%d) gives %#v", i, e.End, got)
		}
		if q.Pending() != 0 {
			t.Fatalf("cut after event %d leaves %d pending bytes", i, q.Pending())
		}
	}
}

// End is relative to the current chunk even when the event started in an earlier one.
func TestEventEndAcrossChunks(t *testing.T) {
	var p Parser
	p.Feed([]byte("event: a\ndata: 1"))
	evs := p.Feed([]byte("\n\nevent: b\ndata: 2\n\n"))
	if len(evs) != 2 || evs[0].End != 2 || evs[1].End != len("\n\nevent: b\ndata: 2\n\n") {
		t.Fatalf("got %#v", evs)
	}
}

// Every split point, including between \r and \n, gives the same events.
func TestEverySplitPoint(t *testing.T) {
	for i := 0; i <= len(stream); i++ {
		var p Parser
		got := stripEnd(append(p.Feed([]byte(stream[:i])), p.Feed([]byte(stream[i:]))...))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("split at %d: got %#v", i, got)
		}
	}
}

func TestByteAtATime(t *testing.T) {
	var p Parser
	var got []Event
	for i := 0; i < len(stream); i++ {
		got = append(got, p.Feed([]byte{stream[i]})...)
	}
	if got = stripEnd(got); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestOverlongLineDropped(t *testing.T) {
	p := Parser{MaxLine: 8}
	p.Feed([]byte("data: 0123456789abcdef"))
	got := p.Feed([]byte("ghij\n\nevent: x\ndata: y\n\n"))
	if p.Dropped != 1 {
		t.Fatalf("dropped = %d", p.Dropped)
	}
	if !reflect.DeepEqual(stripEnd(got), []Event{{Name: "x", Data: "y"}}) {
		t.Fatalf("after drop got %#v", got)
	}
}

// An overlong line that arrives with its newline in the same chunk is dropped too.
func TestOverlongLineWithNewlineDropped(t *testing.T) {
	p := Parser{MaxLine: 8}
	got := p.Feed([]byte("data: 0123456789abcdef\n\nevent: x\ndata: y\n\n"))
	if p.Dropped != 1 {
		t.Fatalf("dropped = %d", p.Dropped)
	}
	if !reflect.DeepEqual(stripEnd(got), []Event{{Name: "x", Data: "y"}}) {
		t.Fatalf("got %#v", got)
	}
}

// An event that never ends must not grow the parser without limit.
func TestOversizeEventIsDropped(t *testing.T) {
	p := Parser{MaxEvent: 4096}
	line := []byte("data: " + string(bytes.Repeat([]byte("x"), 1000)) + "\n")
	for i := 0; i < 100; i++ {
		if evs := p.Feed(line); len(evs) != 0 {
			t.Fatalf("line %d dispatched %d events", i, len(evs))
		}
		if len(p.data) > p.MaxEvent {
			t.Fatalf("line %d: data buffer is %d bytes, cap %d", i, len(p.data), p.MaxEvent)
		}
	}
	if p.Dropped != 1 {
		t.Fatalf("Dropped = %d, want 1", p.Dropped)
	}
	// The blank line ends the dropped event without dispatching it; the next one parses.
	evs := p.Feed([]byte("\nevent: ok\ndata: fine\n\n"))
	if len(evs) != 1 || evs[0].Name != "ok" || evs[0].Data != "fine" {
		t.Fatalf("after the dropped event: %+v", evs)
	}
}

// A lone CR ends a line. When it is the last byte of the stream, Feed cannot
// tell it from the first half of a CRLF; Close settles it.
func TestCloseDispatchesEventEndedByLoneCR(t *testing.T) {
	var p Parser
	if evs := p.Feed([]byte("event: a\rdata: 1\r\r")); len(evs) != 0 {
		t.Fatalf("Feed dispatched %v before the stream ended", evs)
	}
	evs := p.Close()
	if want := []Event{{Name: "a", Data: "1"}}; !reflect.DeepEqual(evs, want) {
		t.Fatalf("Close = %#v", evs)
	}
	if p.Pending() != 0 {
		t.Fatalf("Pending = %d after Close", p.Pending())
	}
}

func TestCloseDiscardsUnfinishedEvent(t *testing.T) {
	for _, s := range []string{"data: 1\n", "data: 1\r", "data: 1", "data: 1\n\ndata: 2\r"} {
		var p Parser
		p.Feed([]byte(s))
		if evs := p.Close(); len(evs) != 0 {
			t.Fatalf("%q: Close = %#v", s, evs)
		}
		// The parser is reset: nothing of the old event leaks into a new one.
		if evs := p.Feed([]byte("data: x\n\n")); len(evs) != 1 || evs[0].Data != "x" || evs[0].Name != "" {
			t.Fatalf("%q: after Close, Feed = %#v", s, evs)
		}
	}
}

func TestCloseAfterCompleteStreamIsEmpty(t *testing.T) {
	var p Parser
	p.Feed([]byte(stream))
	if evs := p.Close(); len(evs) != 0 {
		t.Fatalf("Close = %#v", evs)
	}
}
