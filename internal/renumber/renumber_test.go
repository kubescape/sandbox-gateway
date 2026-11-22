package renumber

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kubescape/sandbox-gateway/internal/sse"
	"github.com/kubescape/sandbox-gateway/internal/streamfmt"
)

func ev(name, data string) string {
	if name == "" {
		return "data: " + data + "\n\n"
	}
	return "event: " + name + "\ndata: " + data + "\n\n"
}

func aBlock(idx int, kind, name string) string {
	block := fmt.Sprintf(`{"type":%q,"text":""}`, kind)
	if name != "" {
		block = fmt.Sprintf(`{"type":%q,"id":"toolu_%d","name":%q,"input":{}}`, kind, idx, name)
	}
	return ev("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":%s}`, idx, block)) +
		ev("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":"<b>"}}`, idx)) +
		ev("content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, idx))
}

const (
	aStart = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n"
	aEnd   = "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
)

// text 0, tool 1 (bash), text 2, with a keep-alive comment in the middle.
func anthropicStream() string {
	return aStart + aBlock(0, "text", "") + ": ping\n\n" + aBlock(1, "tool_use", "bash") + aBlock(2, "text", "") + aEnd
}

func chatChunk(delta, finish string) string {
	return ev("", fmt.Sprintf(`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1730000000,"model":"m","choices":[{"index":0,"delta":%s,"finish_reason":%s}]}`, delta, finish))
}

func chatCall(idx int, id, name string) string {
	return chatChunk(fmt.Sprintf(`{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":""}}]}`, idx, id, name), "null") +
		chatChunk(fmt.Sprintf(`{"tool_calls":[{"index":%d,"function":{"arguments":"{}"}}]}`, idx), "null")
}

// two tool calls, bash (0) then read (1).
func chatStream() string {
	return chatChunk(`{"role":"assistant","content":""}`, "null") +
		chatCall(0, "call_a", "bash") + chatCall(1, "call_b", "read") +
		chatChunk(`{}`, `"tool_calls"`) + ev("", "[DONE]")
}

// function call bash (0) then a message (1).
func responsesStream() string {
	seq := 0
	r := func(typ, body string) string {
		s := ev(typ, fmt.Sprintf(`{"type":%q,"sequence_number":%d,%s}`, typ, seq, body))
		seq++
		return s
	}
	return r("response.created", `"response":{"id":"resp_1","status":"in_progress","output":[]}`) +
		r("response.output_item.added", `"output_index":0,"item":{"id":"fc_1","type":"function_call","name":"bash","arguments":""}`) +
		r("response.function_call_arguments.delta", `"item_id":"fc_1","output_index":0,"delta":"{}"`) +
		r("response.output_item.done", `"output_index":0,"item":{"id":"fc_1","type":"function_call","name":"bash","arguments":"{}"}`) +
		r("response.output_item.added", `"output_index":1,"item":{"id":"msg_1","type":"message","content":[]}`) +
		r("response.output_text.delta", `"item_id":"msg_1","output_index":1,"content_index":0,"delta":"Done."`) +
		r("response.output_item.done", `"output_index":1,"item":{"id":"msg_1","type":"message","content":[]}`) +
		r("response.completed", `"response":{"id":"resp_1","status":"completed","output":[{"id":"fc_1","type":"function_call"},{"id":"msg_1","type":"message"}]}`)
}

func named(name string) Filter {
	return func(it streamfmt.Item) bool { return it.Name == name }
}

func run(f Filter, chunks ...string) string {
	e := New(f)
	var out []byte
	for _, c := range chunks {
		b, err := e.Feed([]byte(c))
		if err != nil {
			panic(err)
		}
		out = append(out, b...)
	}
	return string(append(out, e.Flush()...))
}

func decode(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var p sse.Parser
	var out []map[string]any
	for _, ev := range p.Feed([]byte(stream)) {
		if ev.Data == "[DONE]" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ev.Data), &m); err != nil {
			t.Fatalf("output event is not JSON: %q: %v", ev.Data, err)
		}
		out = append(out, m)
	}
	return out
}

func TestNothingRemovedIsByteIdentical(t *testing.T) {
	never := func(streamfmt.Item) bool { return false }
	for name, s := range map[string]string{"anthropic": anthropicStream(), "chat": chatStream(), "responses": responsesStream()} {
		for i := 0; i <= len(s); i++ {
			if got := run(never, s[:i], s[i:]); got != s {
				t.Fatalf("%s split at %d: output differs from input", name, i)
			}
		}
	}
}

func TestAnthropicRemoveMiddle(t *testing.T) {
	out := run(named("bash"), anthropicStream())
	if strings.Contains(out, "tool_use\",\"id") || strings.Contains(out, "toolu_") {
		t.Fatalf("removed block still in the stream:\n%s", out)
	}
	var idx []int
	for _, m := range decode(t, out) {
		if i, ok := m["index"]; ok {
			idx = append(idx, int(i.(float64)))
		}
	}
	if want := []int{0, 0, 0, 1, 1, 1}; !reflect.DeepEqual(idx, want) {
		t.Fatalf("indexes = %v, want %v", idx, want)
	}
	// Events before the removed block are untouched, byte for byte, and the
	// stream still ends the way it did.
	if !strings.HasPrefix(out, aStart+aBlock(0, "text", "")) || !strings.HasSuffix(out, aEnd) {
		t.Fatalf("untouched events were rewritten:\n%s", out)
	}
	// A rewritten event keeps its payload: no HTML escaping of "<b>".
	if !strings.Contains(out, `"text":"<b>"`) || strings.Count(out, "<b>") != 2 {
		t.Fatalf("payload of a renumbered event changed:\n%s", out)
	}
	if strings.Count(out, "event: content_block_start\n") != 2 {
		t.Fatalf("event names lost:\n%s", out)
	}
}

func TestOpenAIChatRemoveFirstCall(t *testing.T) {
	out := run(named("bash"), chatStream())
	if strings.Contains(out, "call_a") || !strings.HasSuffix(out, "data: [DONE]\n\n") {
		t.Fatalf("output:\n%s", out)
	}
	var calls []map[string]any
	for _, m := range decode(t, out) {
		delta := m["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
		for _, tc := range asList(delta["tool_calls"]) {
			calls = append(calls, tc.(map[string]any))
		}
	}
	if len(calls) != 2 || calls[0]["id"] != "call_b" {
		t.Fatalf("calls = %v", calls)
	}
	for _, c := range calls {
		if c["index"].(float64) != 0 {
			t.Fatalf("call index = %v, want 0", c["index"])
		}
	}
	// The first chunk (role) and the finish chunk are untouched.
	if !strings.HasPrefix(out, chatChunk(`{"role":"assistant","content":""}`, "null")) || !strings.Contains(out, chatChunk(`{}`, `"tool_calls"`)) {
		t.Fatalf("untouched chunks were rewritten:\n%s", out)
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func TestResponsesRemoveFunctionCall(t *testing.T) {
	out := run(named("bash"), responsesStream())
	if strings.Contains(out, "fc_1") {
		t.Fatalf("removed item still in the stream:\n%s", out)
	}
	evs := decode(t, out)
	if len(evs) != 5 {
		t.Fatalf("%d events, want 5", len(evs))
	}
	for i, m := range evs {
		if got := int(m["sequence_number"].(float64)); got != i {
			t.Fatalf("event %d has sequence_number %d", i, got)
		}
		if oi, ok := m["output_index"]; ok && oi.(float64) != 0 {
			t.Fatalf("event %d has output_index %v, want 0", i, oi)
		}
	}
	final := evs[4]["response"].(map[string]any)["output"].([]any)
	if len(final) != 1 || final[0].(map[string]any)["id"] != "msg_1" {
		t.Fatalf("final output = %v", final)
	}
}

func TestRemoveTwo(t *testing.T) {
	s := aStart + aBlock(0, "tool_use", "bash") + aBlock(1, "tool_use", "bash") + aBlock(2, "text", "") + aEnd
	var idx []int
	for _, m := range decode(t, run(named("bash"), s)) {
		if i, ok := m["index"]; ok {
			idx = append(idx, int(i.(float64)))
		}
	}
	if want := []int{0, 0, 0}; !reflect.DeepEqual(idx, want) {
		t.Fatalf("indexes = %v, want %v", idx, want)
	}
}

func TestPartialEventHeld(t *testing.T) {
	e := New(named("bash"))
	block := aBlock(0, "tool_use", "bash")
	half := len(block) / 2
	if out, _ := e.Feed([]byte(aStart + block[:10])); string(out) != aStart {
		t.Fatalf("forwarded part of an incomplete event: %q", out)
	}
	if out, _ := e.Feed([]byte(block[10:half])); len(out) != 0 {
		t.Fatalf("forwarded %q before the item was complete", out)
	}
	if out, _ := e.Feed([]byte(block[half:])); len(out) != 0 {
		t.Fatalf("removed item leaked: %q", out)
	}
	if out, _ := e.Feed([]byte(aEnd)); string(out) != aEnd {
		t.Fatalf("tail = %q", out)
	}
	if out := e.Flush(); len(out) != 0 {
		t.Fatalf("flush = %q", out)
	}
}

func TestFlushReturnsUnfinishedTail(t *testing.T) {
	e := New(named("bash"))
	_, _ = e.Feed([]byte(aStart + "event: content_bl"))
	if out := e.Flush(); string(out) != "event: content_bl" {
		t.Fatalf("flush = %q", out)
	}
}

func TestUnknownFormatPassesThrough(t *testing.T) {
	s := ev("", `{"jsonrpc":"2.0","id":1,"result":{"index":4}}`) + ev("message", `plain text`) + ": comment\n\n"
	if got := run(func(streamfmt.Item) bool { return true }, s); got != s {
		t.Fatalf("unknown stream changed:\n%s", got)
	}
}

func TestFilterAskedOncePerItem(t *testing.T) {
	asked := map[int]int{}
	run(func(it streamfmt.Item) bool { asked[it.Index]++; return false }, chatStream())
	if !reflect.DeepEqual(asked, map[int]int{0: 1, 1: 1}) {
		t.Fatalf("asked = %v", asked)
	}
}

func TestLargeIntegersSurviveRewrite(t *testing.T) {
	s := chatChunk(`{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"bash","arguments":""}}]}`, "null") +
		ev("", `{"id":"c","object":"chat.completion.chunk","created":9007199254740993,"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"b","type":"function","function":{"name":"read","arguments":""}}]},"finish_reason":null}]}`)
	if out := run(named("bash"), s); !strings.Contains(out, `"created":9007199254740993`) {
		t.Fatalf("integer changed in a rewritten event:\n%s", out)
	}
}

// feedAll feeds chunks and returns what was forwarded and the first error.
func feedAll(e *Editor, chunks ...string) (string, error) {
	var out []byte
	for _, c := range chunks {
		b, err := e.Feed([]byte(c))
		out = append(out, b...)
		if err != nil {
			return string(out), err
		}
	}
	return string(append(out, e.Flush()...)), nil
}

// Review: an event over the parser's limits reaches the parser as nothing, so
// it could not be edited. The editor must not forward it as is.
func TestOversizedEventInRemovedItemFailsClosed(t *testing.T) {
	big := strings.Repeat("x", 1<<20+10)
	s := aStart +
		ev("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_0","name":"bash","input":{}}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"`+big+`"}}`) +
		ev("content_block_stop", `{"type":"content_block_stop","index":0}`) + aEnd
	e := New(named("bash"))
	var chunks []string
	for i := 0; i < len(s); i += 64 << 10 {
		chunks = append(chunks, s[i:min(i+64<<10, len(s))])
	}
	out, err := feedAll(e, chunks...)
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("err = %v, want ErrEventTooLarge", err)
	}
	if strings.Contains(out, "xxxxxxxx") || strings.Contains(out, "toolu_0") {
		t.Fatal("part of the removed item was forwarded")
	}
	if b, err := e.Feed([]byte(aEnd)); len(b) != 0 || !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("after the failure Feed returned %q, %v", b, err)
	}
	if b := e.Flush(); len(b) != 0 {
		t.Fatalf("Flush after the failure returned %d bytes", len(b))
	}
}

// Review: a large closing event of a Responses stream (an image output is
// enough) would otherwise be forwarded with the removed item still in it.
func TestOversizedClosingEventFailsClosed(t *testing.T) {
	s := responsesStream()
	i := strings.Index(s, "event: response.completed")
	big := ev("response.completed", `{"type":"response.completed","sequence_number":7,"response":{"id":"resp_1","status":"completed","output":[{"id":"fc_1","type":"function_call"},{"id":"img","type":"image_generation_call","result":"`+strings.Repeat("A", 2<<20)+`"}]}}`)
	out, err := feedAll(New(named("bash")), s[:i], big)
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("err = %v, want ErrEventTooLarge", err)
	}
	if strings.Contains(out, "response.completed") {
		t.Fatal("the unedited closing event was forwarded")
	}
}

// Review: the editor held every byte of an event that never ended.
func TestPendingIsBounded(t *testing.T) {
	for name, line := range map[string]string{
		"no newline":    strings.Repeat("y", 64<<10),
		"no blank line": "data: " + strings.Repeat("y", 64<<10) + "\n",
	} {
		e := New(named("bash"))
		var err error
		for i := 0; i < 512 && err == nil; i++ { // up to 32 MiB
			_, err = e.Feed([]byte(line))
			if len(e.pending) > maxPending {
				t.Fatalf("%s: holding %d bytes, over the %d cap", name, len(e.pending), maxPending)
			}
		}
		if !errors.Is(err, ErrEventTooLarge) {
			t.Fatalf("%s: err = %v, want ErrEventTooLarge", name, err)
		}
		if len(e.pending) != 0 {
			t.Fatalf("%s: still holding %d bytes after the failure", name, len(e.pending))
		}
	}
}

// Review: tool call indexes in OpenAI chat count per choice.
func TestOpenAIChatToolCallsArePerChoice(t *testing.T) {
	two := func(c0, c1 string) string {
		return ev("", `{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[`+c0+`,`+c1+`]}`)
	}
	call := func(choice int, id, name string) string {
		return fmt.Sprintf(`{"index":%d,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":""}}]},"finish_reason":null}`, choice, id, name)
	}
	s := two(call(0, "call_a", "bash"), call(1, "call_b", "read")) + ev("", "[DONE]")
	out := run(named("bash"), s)
	if strings.Contains(out, "call_a") || !strings.Contains(out, "call_b") {
		t.Fatalf("output:\n%s", out)
	}
	m := decode(t, out)[0]
	ch := m["choices"].([]any)
	c1 := ch[1].(map[string]any)["delta"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	if c1["index"].(float64) != 0 {
		t.Fatalf("choice 1's call moved to index %v", c1["index"])
	}
}
