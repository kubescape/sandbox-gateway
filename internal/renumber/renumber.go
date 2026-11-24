// Package renumber removes items from a streamed response and renumbers the
// items after them, so the client sees a stream with no gap in its indexes.
// SDK stream helpers index into a list by these numbers; a gap makes them
// raise.
//
// It handles the three formats internal/streamfmt knows. An event that needs
// no change is forwarded byte for byte; only an event whose index or sequence
// number changes is serialised again. A stream in any other format passes
// through untouched.
//
// The stop reason is left as the provider sent it, also when the removed item
// was the reason the provider stopped.
//
// An event too large to parse cannot be edited. Before the stream has shown
// one of the known formats there is nothing to edit, so the editor stops
// parsing and passes the rest of the stream through. Once the format is known,
// forwarding such an event as it came could leak a removed item or a stale
// index, so the editor fails closed: Feed returns ErrEventTooLarge, forwards
// nothing more, and the caller ends the stream.
package renumber

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/kubescape/sandbox-gateway/internal/sse"
	"github.com/kubescape/sandbox-gateway/internal/streamfmt"
)

// Parser limits. An event is at most maxEvent bytes of data and no line is
// longer than maxLine. The editor holds at most maxPending bytes as received:
// the event that has not ended plus the OpenAI chat events waiting on a tool
// call's name. Bytes as received include each line's field name and line end,
// so the limit leaves room above maxEvent for an event of many short lines.
const (
	maxLine    = 1 << 20
	maxEvent   = 4 << 20
	maxPending = 2*maxEvent + maxLine
)

// ErrEventTooLarge means the stream had an event over the parser's limits. The
// editor could not read it, so it stopped forwarding; the caller must end the
// stream.
var ErrEventTooLarge = errors.New("renumber: streamed event too large to edit")

// itemKey names an item. Choice is the OpenAI chat choice; it is 0 for the
// formats that have one item list.
type itemKey struct{ choice, index int }

// Filter decides whether an item is removed. It is asked once per item, at the
// item's first event.
type Filter func(streamfmt.Item) (remove bool)

// Editor edits one response stream. It is used by one goroutine.
type Editor struct {
	remove  Filter
	parser  sse.Parser
	pending []byte // bytes received that do not yet end an event
	format  streamfmt.Format
	seen    map[itemKey]bool // item -> removed
	dropped int              // events dropped so far (Responses sequence numbers)
	err     error            // set once the editor has failed closed
	through bool             // passing the stream through unread (see the package doc)

	// OpenAI chat: tool calls seen without a name yet, and the events held
	// until they get one.
	undecided map[itemKey]bool
	queue     []queued
	queued    int // bytes in queue
}

// queued is an OpenAI chat event held until every tool call in flight has a
// name the filter can judge.
type queued struct {
	ev  sse.Event
	raw []byte
	p   streamfmt.Event
}

// New returns an editor that removes the items remove picks.
func New(remove Filter) *Editor {
	e := &Editor{remove: remove, seen: map[itemKey]bool{}, undecided: map[itemKey]bool{}}
	e.parser.MaxLine, e.parser.MaxEvent = maxLine, maxEvent
	return e
}

// Feed takes the next chunk of the response body and returns the bytes to
// forward for it. It holds back an incomplete trailing event, so the result
// can be shorter than the chunk, or empty.
//
// When the stream has an event too large to parse after its format is known,
// Feed returns ErrEventTooLarge, and returns it again on every later call with
// nothing to forward.
func (e *Editor) Feed(chunk []byte) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if e.through {
		return chunk, nil
	}
	droppedBefore := e.parser.Dropped
	events := e.parser.Feed(chunk)
	if e.parser.Dropped != droppedBefore {
		if e.format == streamfmt.Unknown {
			return e.passThrough(chunk), nil
		}
		return nil, e.fail()
	}
	carried := len(e.pending)
	e.pending = append(e.pending, chunk...)
	var out []byte
	start := 0
	for _, ev := range events {
		end := carried + ev.End
		out = append(out, e.event(ev, e.pending[start:end])...)
		start = end
	}
	e.pending = append(e.pending[:0], e.pending[start:]...)
	if len(e.pending)+e.queued > maxPending {
		if e.format == streamfmt.Unknown {
			return append(out, e.passThrough(nil)...), nil
		}
		return nil, e.fail()
	}
	return out, nil
}

// passThrough stops editing a stream whose format is not one the editor knows:
// it returns what it holds and chunk, and Feed returns later chunks as they
// come.
func (e *Editor) passThrough(chunk []byte) []byte {
	out := append(e.pending, chunk...)
	e.through, e.pending = true, nil
	return out
}

// fail stops the editor: what it holds is dropped and nothing more is forwarded.
func (e *Editor) fail() error {
	e.err, e.pending, e.queue, e.queued = ErrEventTooLarge, nil, nil, 0
	return e.err
}

// Flush ends the stream and returns the last bytes to forward. An event that
// only the end of the stream completes (its blank line is a lone CR, which
// could have been the start of a CRLF until the stream ended) goes through the
// editor like any other event.
//
// What is left after that is an event that never got its blank line. An SSE
// client discards such an event, so it is dropped here too, rather than
// forwarded unread where it could carry a removed item. A stream in a format
// the editor does not edit gets its tail back unchanged. After a failure Flush
// returns nothing.
func (e *Editor) Flush() []byte {
	if e.err != nil || e.through {
		return nil
	}
	var out []byte
	start := 0
	for _, ev := range e.parser.Close() {
		out = append(out, e.event(ev, e.pending[start:])...)
		start = len(e.pending)
	}
	// Chat events still waiting on a tool call's name: the stream ended
	// without one, so the filter judges the call without its name.
	out = append(out, e.settle()...)
	if tail := e.pending[start:]; len(tail) > 0 && e.format == streamfmt.Unknown {
		out = append(out, tail...)
	}
	e.pending = nil
	return out
}

// event returns the bytes to forward for one complete event. raw is the event
// as received, with any comment lines that came before it.
func (e *Editor) event(ev sse.Event, raw []byte) []byte {
	p := streamfmt.Parse(ev)
	if p.Format == streamfmt.Unknown {
		return raw
	}
	if e.format == streamfmt.Unknown {
		e.format = p.Format
	}
	if p.Format != e.format {
		return raw
	}
	for _, it := range p.Starts {
		k := itemKey{it.Choice, it.Index}
		if _, ok := e.seen[k]; !ok {
			e.seen[k] = e.remove(it)
		}
	}
	switch e.format {
	case streamfmt.Anthropic:
		return e.indexed(ev, raw, p, "index")
	case streamfmt.OpenAIChat:
		return e.chatEvent(ev, raw, p)
	case streamfmt.OpenAIResponses:
		return e.responses(ev, raw, p)
	}
	return raw
}

// chatEvent handles an OpenAI chat event. A tool call is judged at its first
// chunk that carries its id or name. Until every call in flight has had one,
// the events are held, so a call named in a later chunk is still judged with
// its name. The end of the choices (a finish reason, or [DONE]) settles the
// calls that never got one.
func (e *Editor) chatEvent(ev sse.Event, raw []byte, p streamfmt.Event) []byte {
	for _, it := range p.Starts {
		delete(e.undecided, itemKey{it.Choice, it.Index})
	}
	for _, tc := range p.ToolCalls {
		if k := (itemKey{tc.Choice, tc.Index}); !hasKey(e.seen, k) {
			e.undecided[k] = true
		}
	}
	if len(e.undecided) > 0 && !p.Done && p.StopReason == "" {
		e.queue = append(e.queue, queued{ev, bytes.Clone(raw), p})
		e.queued += len(raw)
		return nil
	}
	return append(e.settle(), e.chat(ev, raw, p)...)
}

// settle judges the tool calls that never got a name and returns the held
// chat events, edited.
func (e *Editor) settle() []byte {
	for k := range e.undecided {
		e.seen[k] = e.remove(streamfmt.Item{Format: streamfmt.OpenAIChat, Choice: k.choice, Index: k.index, Kind: "function"})
		delete(e.undecided, k)
	}
	var out []byte
	for _, q := range e.queue {
		out = append(out, e.chat(q.ev, q.raw, q.p)...)
	}
	e.queue, e.queued = nil, 0
	return out
}

func hasKey(m map[itemKey]bool, k itemKey) bool {
	_, ok := m[k]
	return ok
}

// shift is how far an item moves down: the number of removed items before it
// in the same list.
func (e *Editor) shift(k itemKey) int {
	n := 0
	for i, removed := range e.seen {
		if removed && i.choice == k.choice && i.index < k.index {
			n++
		}
	}
	return n
}

// indexed handles an event that belongs to at most one item, named by key.
func (e *Editor) indexed(ev sse.Event, raw []byte, p streamfmt.Event, key string) []byte {
	if !p.HasIndex {
		return raw
	}
	k := itemKey{0, p.Index}
	if e.seen[k] {
		e.dropped++
		return nil
	}
	sh := e.shift(k)
	if sh == 0 {
		return raw
	}
	return rewrite(ev, raw, func(m map[string]any) bool {
		m[key] = p.Index - sh
		return true
	})
}

func (e *Editor) chat(ev sse.Event, raw []byte, p streamfmt.Event) []byte {
	touched := false
	for _, tc := range p.ToolCalls {
		k := itemKey{tc.Choice, tc.Index}
		if _, ok := e.seen[k]; !ok {
			// A tool call whose first chunk carried neither id nor name.
			e.seen[k] = e.remove(streamfmt.Item{Format: streamfmt.OpenAIChat, Choice: tc.Choice, Index: tc.Index, Kind: "function"})
		}
		if e.seen[k] || e.shift(k) > 0 {
			touched = true
		}
	}
	if !touched {
		return raw
	}
	return rewrite(ev, raw, func(m map[string]any) bool {
		keep := false
		choices, _ := m["choices"].([]any)
		for _, c := range choices {
			choice, _ := c.(map[string]any)
			ci := 0
			if n, ok := choice["index"].(json.Number); ok {
				if v, err := n.Int64(); err == nil {
					ci = int(v)
				}
			}
			delta, _ := choice["delta"].(map[string]any)
			calls, _ := delta["tool_calls"].([]any)
			kept := calls[:0]
			for _, tc := range calls {
				call, _ := tc.(map[string]any)
				n, ok := call["index"].(json.Number)
				i64, err := n.Int64()
				if !ok || err != nil {
					kept = append(kept, tc)
					continue
				}
				k := itemKey{ci, int(i64)}
				if e.seen[k] {
					continue
				}
				call["index"] = k.index - e.shift(k)
				kept = append(kept, tc)
			}
			if len(kept) > 0 {
				delta["tool_calls"] = kept
			} else {
				delete(delta, "tool_calls")
			}
			if len(delta) > 0 || choice["finish_reason"] != nil || choice["logprobs"] != nil {
				keep = true
			}
		}
		// Usage and the like ride on the chunk, not on a choice.
		return keep || m["usage"] != nil
	})
}

func (e *Editor) responses(ev sse.Event, raw []byte, p streamfmt.Event) []byte {
	k := itemKey{0, p.Index}
	if p.HasIndex && e.seen[k] {
		e.dropped++
		return nil
	}
	sh := 0
	if p.HasIndex {
		sh = e.shift(k)
	}
	anyRemoved := false
	for _, removed := range e.seen {
		anyRemoved = anyRemoved || removed
	}
	editsOutput := p.Done && anyRemoved
	if sh == 0 && e.dropped == 0 && !editsOutput {
		return raw
	}
	return rewrite(ev, raw, func(m map[string]any) bool {
		if sh > 0 {
			m["output_index"] = p.Index - sh
		}
		if n, ok := m["sequence_number"].(json.Number); ok {
			if seq, err := n.Int64(); err == nil {
				m["sequence_number"] = seq - int64(e.dropped)
			}
		}
		// The closing event repeats the whole output list, by position.
		if resp, ok := m["response"].(map[string]any); ok && p.Done {
			if output, ok := resp["output"].([]any); ok {
				kept := make([]any, 0, len(output))
				for i, item := range output {
					if !e.seen[itemKey{0, i}] {
						kept = append(kept, item)
					}
				}
				resp["output"] = kept
			}
		}
		return true
	})
}

// rewrite decodes the event's payload, lets edit change it, and serialises
// the event again. edit returns false to drop the event. If the payload cannot
// be decoded the event is forwarded as it came.
func rewrite(ev sse.Event, raw []byte, edit func(map[string]any) (keep bool)) []byte {
	dec := json.NewDecoder(strings.NewReader(ev.Data))
	dec.UseNumber() // integers outside float64's exact range must survive
	var m map[string]any
	if dec.Decode(&m) != nil {
		return raw
	}
	if !edit(m) {
		return nil
	}
	var payload bytes.Buffer
	enc := json.NewEncoder(&payload)
	enc.SetEscapeHTML(false)
	if enc.Encode(m) != nil {
		return raw
	}
	return replaceData(raw, bytes.TrimSuffix(payload.Bytes(), []byte("\n")))
}

// replaceData returns raw with its data lines replaced by one line carrying
// payload, at the place of the first. Every other line (event, id, retry,
// comments, the blank line that ends the event) is kept as it came. Line
// ends become LF.
func replaceData(raw, payload []byte) []byte {
	var b bytes.Buffer
	written := false
	for len(raw) > 0 {
		line := raw
		raw = nil
		if i := bytes.IndexAny(line, "\r\n"); i >= 0 {
			adv := i + 1
			if line[i] == '\r' && i+1 < len(line) && line[i+1] == '\n' {
				adv = i + 2
			}
			line, raw = line[:i], line[adv:]
		}
		if isData(line) {
			if !written {
				b.WriteString("data: ")
				b.Write(payload)
				b.WriteByte('\n')
				written = true
			}
			continue
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// isData reports whether an SSE line is a data field.
func isData(line []byte) bool {
	rest, ok := bytes.CutPrefix(line, []byte("data"))
	return ok && (len(rest) == 0 || rest[0] == ':')
}
