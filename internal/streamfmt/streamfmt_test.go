package streamfmt

import (
	"reflect"
	"testing"

	"github.com/kubescape/sandbox-gateway/internal/sse"
)

func TestTrackerPerFormat(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream string
		format Format
		stop   string
		items  []Item
	}{
		{"anthropic", anthropicBaseline(), Anthropic, "tool_use", []Item{
			{Format: Anthropic, Index: 0, Kind: "text", Name: ""}, {Format: Anthropic, Index: 1, Kind: "tool_use", Name: "bash"}}},
		{"openai chat", chatBaseline(), OpenAIChat, "tool_calls", []Item{
			{Format: OpenAIChat, Index: 0, Kind: "function", Name: "bash"}, {Format: OpenAIChat, Index: 1, Kind: "function", Name: "bash"}}},
		{"openai responses", responsesBaseline(), OpenAIResponses, "completed", []Item{
			{Format: OpenAIResponses, Index: 0, Kind: "function_call", Name: "bash"}, {Format: OpenAIResponses, Index: 1, Kind: "message", Name: ""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tr Tracker
			var items []Item
			for _, ev := range events(tc.stream) {
				if tr.Done {
					t.Fatal("Done before the last event")
				}
				items = append(items, Parse(ev).Starts...)
				tr.Event(ev)
			}
			if tr.Format != tc.format || tr.StopReason != tc.stop || !tr.Done {
				t.Fatalf("format=%v stop=%q done=%v", tr.Format, tr.StopReason, tr.Done)
			}
			if open := tr.Open(); len(open) != 0 {
				t.Fatalf("items still open at the end: %v", open)
			}
			if !reflect.DeepEqual(items, tc.items) {
				t.Fatalf("items = %+v", items)
			}
		})
	}
}

func TestOpenWhileStreaming(t *testing.T) {
	var tr Tracker
	evs := events(anthropicBaseline())
	for _, ev := range evs[:6] { // up to the tool block's delta
		tr.Event(ev)
	}
	if got := tr.Open(); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("open = %v, want [1]", got)
	}
}

func TestDetect(t *testing.T) {
	for data, want := range map[string]Format{
		`{"type":"message_start"}`:                        Anthropic,
		`{"type":"content_block_delta","index":0}`:        Anthropic,
		`{"object":"chat.completion.chunk","choices":[]}`: OpenAIChat,
		`[DONE]`: OpenAIChat,
		`{"type":"response.created","sequence_number":0}`: OpenAIResponses,
		`{"type":"ping"}`: Unknown,
		`{"type":"error","error":{"type":"api_error"}}`: Unknown,
		`not json`: Unknown,
		`{"jsonrpc":"2.0","method":"tools/call","id":"1"}`: Unknown,
	} {
		if got := Detect(sse.Event{Data: data}); got != want {
			t.Errorf("%s: %v, want %v", data, got, want)
		}
	}
}

func TestEventIndexes(t *testing.T) {
	e := Parse(sse.Event{Data: `{"type":"content_block_stop","index":3}`})
	if !e.HasIndex || e.Index != 3 || !e.Stops {
		t.Fatalf("%+v", e)
	}
	// message_delta has no item index even though other payloads use "index".
	if e := Parse(sse.Event{Data: `{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`}); e.HasIndex || e.StopReason != "end_turn" {
		t.Fatalf("%+v", e)
	}
	// A Responses text delta is a string, an Anthropic one an object: both parse.
	e = Parse(sse.Event{Data: `{"type":"response.output_text.delta","output_index":2,"delta":"Done."}`})
	if e.Format != OpenAIResponses || e.Index != 2 || !e.HasIndex {
		t.Fatalf("%+v", e)
	}
	e = Parse(sse.Event{Data: `{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"x"}},{"index":2,"id":"c","function":{"name":"f"}}]},"finish_reason":null}]}`})
	if !reflect.DeepEqual(e.ToolCalls, []ToolRef{{0, 0}, {0, 2}}) || len(e.Starts) != 1 || e.Starts[0].Index != 2 || e.Starts[0].Name != "f" {
		t.Fatalf("%+v", e)
	}
	// Tool call indexes are per choice: two choices can each have call 0.
	e = Parse(sse.Event{Data: `{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"f"}}]}},{"index":1,"delta":{"tool_calls":[{"index":0,"id":"b","function":{"name":"g"}}]}}]}`})
	if !reflect.DeepEqual(e.ToolCalls, []ToolRef{{0, 0}, {1, 0}}) || len(e.Starts) != 2 || e.Starts[1].Choice != 1 || e.Starts[1].Name != "g" {
		t.Fatalf("%+v", e)
	}
}

func TestTrackerIgnoresOtherFormats(t *testing.T) {
	var tr Tracker
	tr.Event(sse.Event{Data: `{"type":"message_start"}`})
	tr.Event(sse.Event{Data: `[DONE]`})
	if tr.Format != Anthropic || tr.Done {
		t.Fatalf("%+v", tr)
	}
}
