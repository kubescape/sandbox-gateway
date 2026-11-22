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
package renumber

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/kubescape/sandbox-gateway/internal/sse"
	"github.com/kubescape/sandbox-gateway/internal/streamfmt"
)

// Filter decides whether an item is removed. It is asked once per item, at the
// item's first event.
type Filter func(streamfmt.Item) (remove bool)

// Editor edits one response stream. It is used by one goroutine.
type Editor struct {
	remove  Filter
	parser  sse.Parser
	pending []byte // bytes received that do not yet end an event
	format  streamfmt.Format
	seen    map[int]bool // item index -> removed
	dropped int          // events dropped so far (Responses sequence numbers)
}

// New returns an editor that removes the items remove picks.
func New(remove Filter) *Editor {
	return &Editor{remove: remove, seen: map[int]bool{}}
}

// Feed takes the next chunk of the response body and returns the bytes to
// forward for it. It holds back an incomplete trailing event, so the result
// can be shorter than the chunk, or empty.
func (e *Editor) Feed(chunk []byte) []byte {
	events := e.parser.Feed(chunk)
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
	return out
}

// Flush returns what is still held when the stream ends: the bytes of an
// event that never completed.
func (e *Editor) Flush() []byte {
	out := e.pending
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
		if _, ok := e.seen[it.Index]; !ok {
			e.seen[it.Index] = e.remove(it)
		}
	}
	switch e.format {
	case streamfmt.Anthropic:
		return e.indexed(ev, raw, p, "index")
	case streamfmt.OpenAIChat:
		return e.chat(ev, raw, p)
	case streamfmt.OpenAIResponses:
		return e.responses(ev, raw, p)
	}
	return raw
}

// shift is how far item idx moves down: the number of removed items before it.
func (e *Editor) shift(idx int) int {
	n := 0
	for i, removed := range e.seen {
		if removed && i < idx {
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
	if e.seen[p.Index] {
		e.dropped++
		return nil
	}
	sh := e.shift(p.Index)
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
	for _, i := range p.ToolIndexes {
		if _, ok := e.seen[i]; !ok {
			// A tool call whose first chunk carried neither id nor name.
			e.seen[i] = e.remove(streamfmt.Item{Format: streamfmt.OpenAIChat, Index: i, Kind: "function"})
		}
		if e.seen[i] || e.shift(i) > 0 {
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
				i := int(i64)
				if e.seen[i] {
					continue
				}
				call["index"] = i - e.shift(i)
				kept = append(kept, tc)
			}
			if len(kept) > 0 {
				delta["tool_calls"] = kept
			} else {
				delete(delta, "tool_calls")
			}
			if len(delta) > 0 || choice["finish_reason"] != nil {
				keep = true
			}
		}
		return keep
	})
}

func (e *Editor) responses(ev sse.Event, raw []byte, p streamfmt.Event) []byte {
	if p.HasIndex {
		if e.seen[p.Index] {
			e.dropped++
			return nil
		}
	}
	sh := 0
	if p.HasIndex {
		sh = e.shift(p.Index)
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
					if !e.seen[i] {
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
	var b bytes.Buffer
	if ev.Name != "" {
		b.WriteString("event: " + ev.Name + "\n")
	}
	b.WriteString("data: ")
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(m) != nil { // Encode ends the payload with one newline
		return raw
	}
	b.WriteByte('\n')
	return b.Bytes()
}
