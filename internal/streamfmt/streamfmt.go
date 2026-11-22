// Package streamfmt recognises the streamed response formats the gateway sees
// and reads from each event the few things the framework acts on: which item
// the event belongs to, whether it starts or ends one, and how the stream ended.
//
// Three formats are known: Anthropic Messages, OpenAI Chat Completions and
// OpenAI Responses. All three arrive as server-sent events with a JSON payload.
// Anything else is Unknown and is passed through untouched by callers.
package streamfmt

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/kubescape/sandbox-gateway/internal/sse"
)

// Format is a streamed response format.
type Format int

const (
	Unknown Format = iota
	Anthropic
	OpenAIChat
	OpenAIResponses
)

func (f Format) String() string {
	switch f {
	case Anthropic:
		return "anthropic"
	case OpenAIChat:
		return "openai-chat"
	case OpenAIResponses:
		return "openai-responses"
	}
	return "unknown"
}

// Item is one streamed content item, as seen at its first event: an Anthropic
// content block, an OpenAI chat tool call, or an OpenAI Responses output item.
type Item struct {
	Format Format
	Index  int
	Kind   string // "text", "tool_use", "function", "function_call", "message", ...
	Name   string // the tool or function name, when the item has one
}

// Event is what one server-sent event means to the framework.
type Event struct {
	Format Format
	Type   string // the payload's "type"; empty for OpenAI chat chunks
	// Index is the item this event belongs to: the Anthropic "index" or the
	// Responses "output_index". HasIndex is false for events about the whole
	// message, and always for OpenAI chat, whose chunks can carry several
	// tool calls (see Starts and ToolIndexes).
	Index    int
	HasIndex bool
	Starts   []Item // items whose first event this is
	Stops    bool   // this event ends item Index
	// ToolIndexes are the tool call indexes an OpenAI chat chunk carries.
	ToolIndexes []int
	StopReason  string
	Done        bool // the stream is complete
}

// payload is the union of the fields read from the three formats.
type payload struct {
	Type         string          `json:"type"`
	Object       string          `json:"object"`
	Index        *int            `json:"index"`
	OutputIndex  *int            `json:"output_index"`
	Delta        json.RawMessage `json:"delta"`
	ContentBlock *struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"content_block"`
	Item *struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"item"`
	Response *struct {
		Status string `json:"status"`
	} `json:"response"`
	Choices []struct {
		FinishReason *string `json:"finish_reason"`
		Delta        struct {
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
}

// Detect reports the format an event belongs to.
func Detect(ev sse.Event) Format { return Parse(ev).Format }

// Parse reads one event. An event that is not JSON, or not of a known format,
// comes back with Format Unknown; the OpenAI chat terminator "[DONE]" is the
// one exception and comes back as an OpenAIChat event with Done set.
func Parse(ev sse.Event) Event {
	if strings.TrimSpace(ev.Data) == "[DONE]" {
		return Event{Format: OpenAIChat, Done: true}
	}
	var p payload
	if json.Unmarshal([]byte(ev.Data), &p) != nil {
		return Event{}
	}
	switch {
	case strings.HasPrefix(p.Type, "message_") || strings.HasPrefix(p.Type, "content_block_"):
		return anthropicEvent(p)
	case p.Object == "chat.completion.chunk":
		return chatEvent(p)
	case strings.HasPrefix(p.Type, "response."):
		return responsesEvent(p)
	}
	return Event{Type: p.Type}
}

func anthropicEvent(p payload) Event {
	e := Event{Format: Anthropic, Type: p.Type}
	if p.Index != nil && strings.HasPrefix(p.Type, "content_block_") {
		e.Index, e.HasIndex = *p.Index, true
	}
	switch p.Type {
	case "content_block_start":
		if e.HasIndex {
			it := Item{Format: Anthropic, Index: e.Index}
			if p.ContentBlock != nil {
				it.Kind, it.Name = p.ContentBlock.Type, p.ContentBlock.Name
			}
			e.Starts = []Item{it}
		}
	case "content_block_stop":
		e.Stops = e.HasIndex
	case "message_delta":
		var d struct {
			StopReason string `json:"stop_reason"`
		}
		if json.Unmarshal(p.Delta, &d) == nil {
			e.StopReason = d.StopReason
		}
	case "message_stop":
		e.Done = true
	}
	return e
}

func chatEvent(p payload) Event {
	e := Event{Format: OpenAIChat}
	for _, c := range p.Choices {
		if c.FinishReason != nil && *c.FinishReason != "" {
			e.StopReason = *c.FinishReason
		}
		for _, tc := range c.Delta.ToolCalls {
			e.ToolIndexes = append(e.ToolIndexes, tc.Index)
			// Only the first chunk of a tool call carries its id and name.
			if tc.ID != "" || tc.Function.Name != "" {
				kind := tc.Type
				if kind == "" {
					kind = "function"
				}
				e.Starts = append(e.Starts, Item{Format: OpenAIChat, Index: tc.Index, Kind: kind, Name: tc.Function.Name})
			}
		}
	}
	return e
}

func responsesEvent(p payload) Event {
	e := Event{Format: OpenAIResponses, Type: p.Type}
	if p.OutputIndex != nil {
		e.Index, e.HasIndex = *p.OutputIndex, true
	}
	switch p.Type {
	case "response.output_item.added":
		if e.HasIndex {
			it := Item{Format: OpenAIResponses, Index: e.Index}
			if p.Item != nil {
				it.Kind, it.Name = p.Item.Type, p.Item.Name
			}
			e.Starts = []Item{it}
		}
	case "response.output_item.done":
		e.Stops = e.HasIndex
	case "response.completed", "response.incomplete", "response.failed":
		e.Done = true
		if p.Response != nil {
			e.StopReason = p.Response.Status
		}
	}
	return e
}

// Tracker follows one response stream. The zero value is ready to use.
type Tracker struct {
	Format     Format // set by the first recognised event
	StopReason string
	Done       bool
	open       map[int]bool
}

// Event takes the next event of the stream.
func (t *Tracker) Event(ev sse.Event) { t.Parsed(Parse(ev)) }

// Parsed takes an event the caller has already parsed.
func (t *Tracker) Parsed(e Event) {
	if e.Format == Unknown {
		return
	}
	if t.Format == Unknown {
		t.Format = e.Format
	}
	if e.Format != t.Format {
		return
	}
	// OpenAI chat tool calls have no closing event, so only the two formats
	// with one are tracked as open.
	if e.Format != OpenAIChat {
		for _, it := range e.Starts {
			if t.open == nil {
				t.open = map[int]bool{}
			}
			t.open[it.Index] = true
		}
		if e.Stops {
			delete(t.open, e.Index)
		}
	}
	if e.StopReason != "" {
		t.StopReason = e.StopReason
	}
	if e.Done {
		t.Done = true
	}
}

// Open returns the indexes of items that were started and not ended, in order.
func (t *Tracker) Open() []int {
	out := make([]int, 0, len(t.open))
	for i := range t.open {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}
