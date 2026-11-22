package streamfmt

import (
	"fmt"
	"strings"

	"github.com/kubescape/sandbox-gateway/internal/sse"
)

// The streams below have the shape of the mock provider's baseline scenarios
// (test/mock-anthropic/scenarios.go): a tool call among other content.

func ev(name, data string) string {
	if name == "" {
		return "data: " + data + "\n\n"
	}
	return "event: " + name + "\ndata: " + data + "\n\n"
}

func anthropicBaseline() string {
	var b strings.Builder
	b.WriteString(ev("message_start", `{"type":"message_start","message":{"id":"msg_1","content":[],"stop_reason":null}}`))
	b.WriteString(ev("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`))
	b.WriteString(ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me look."}}`))
	b.WriteString(ev("content_block_stop", `{"type":"content_block_stop","index":0}`))
	b.WriteString(ev("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}`))
	b.WriteString(ev("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{}"}}`))
	b.WriteString(ev("content_block_stop", `{"type":"content_block_stop","index":1}`))
	b.WriteString(ev("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":10}}`))
	b.WriteString(ev("message_stop", `{"type":"message_stop"}`))
	return b.String()
}

func chatChunk(delta, finish string) string {
	return ev("", fmt.Sprintf(`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1730000000,"model":"m","choices":[{"index":0,"delta":%s,"finish_reason":%s}]}`, delta, finish))
}

func chatBaseline() string {
	var b strings.Builder
	b.WriteString(chatChunk(`{"role":"assistant","content":""}`, "null"))
	for i, id := range []string{"call_a", "call_b"} {
		b.WriteString(chatChunk(fmt.Sprintf(`{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":"bash","arguments":""}}]}`, i, id), "null"))
		b.WriteString(chatChunk(fmt.Sprintf(`{"tool_calls":[{"index":%d,"function":{"arguments":"{}"}}]}`, i), "null"))
	}
	b.WriteString(chatChunk(`{}`, `"tool_calls"`))
	b.WriteString(ev("", "[DONE]"))
	return b.String()
}

func responsesBaseline() string {
	seq := 0
	r := func(typ, body string) string {
		s := ev(typ, fmt.Sprintf(`{"type":%q,"sequence_number":%d,%s}`, typ, seq, body))
		seq++
		return s
	}
	var b strings.Builder
	b.WriteString(r("response.created", `"response":{"id":"resp_1","status":"in_progress","output":[]}`))
	b.WriteString(r("response.output_item.added", `"output_index":0,"item":{"id":"fc_1","type":"function_call","name":"bash","arguments":"","status":"in_progress"}`))
	b.WriteString(r("response.function_call_arguments.delta", `"item_id":"fc_1","output_index":0,"delta":"{}"`))
	b.WriteString(r("response.output_item.done", `"output_index":0,"item":{"id":"fc_1","type":"function_call","name":"bash","arguments":"{}","status":"completed"}`))
	b.WriteString(r("response.output_item.added", `"output_index":1,"item":{"id":"msg_1","type":"message","role":"assistant","status":"in_progress","content":[]}`))
	b.WriteString(r("response.output_text.delta", `"item_id":"msg_1","output_index":1,"content_index":0,"delta":"Done."`))
	b.WriteString(r("response.output_item.done", `"output_index":1,"item":{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[]}`))
	b.WriteString(r("response.completed", `"response":{"id":"resp_1","status":"completed","output":[{"id":"fc_1","type":"function_call"},{"id":"msg_1","type":"message"}]}`))
	return b.String()
}

func events(stream string) []sse.Event {
	var p sse.Parser
	return p.Feed([]byte(stream))
}
