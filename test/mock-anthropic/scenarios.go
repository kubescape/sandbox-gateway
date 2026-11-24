package main

// S4 scenarios: scripted streams shaped the way a rewriting gateway would emit
// them (a tool call removed, indexes renumbered or left with a gap, a stop or
// finish reason rewritten, an error mid-stream). The client asks for one by
// sending it as the model name. They test what SDKs do with the bytes; the
// rewriting itself is the processor's job.

import (
	"fmt"
	"net/http"
	"strings"
)

func sse(w http.ResponseWriter, event, data string) {
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// --- Anthropic Messages ---------------------------------------------------

func aStart(w http.ResponseWriter, model string) {
	sse(w, "message_start", fmt.Sprintf(`{"type":"message_start","message":{"id":"msg_s4","type":"message","role":"assistant","model":%q,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":0}}}`, model))
}

func aText(w http.ResponseWriter, idx int, text string) {
	sse(w, "content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`, idx))
	sse(w, "content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%q}}`, idx, text))
	sse(w, "content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, idx))
}

func aTool(w http.ResponseWriter, idx int) {
	sse(w, "content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":"toolu_s4","name":"bash","input":{}}}`, idx))
	sse(w, "content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\": \"ls\"}"}}`, idx))
	sse(w, "content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, idx))
}

func aEnd(w http.ResponseWriter, stop string) {
	sse(w, "message_delta", fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":%q,"stop_sequence":null},"usage":{"output_tokens":10}}`, stop))
	sse(w, "message_stop", `{"type":"message_stop"}`)
}

// anthropicScenario serves model names starting with "s4-a-". It reports false
// for other models.
func anthropicScenario(w http.ResponseWriter, model string) bool {
	if !strings.HasPrefix(model, "s4-a-") {
		return false
	}
	w.Header().Set("content-type", "text/event-stream")
	aStart(w, model)
	switch model {
	case "s4-a-baseline": // text, tool; stop_reason tool_use
		aText(w, 0, "Let me look.")
		aTool(w, 1)
		aEnd(w, "tool_use")
	case "s4-a-text-tool-text": // text, tool, text; stop_reason tool_use. Removing the
		// tool renumbers the second text block, which s4-a-baseline cannot show.
		aText(w, 0, "Let me look.")
		aTool(w, 1)
		aText(w, 2, "Done.")
		aEnd(w, "tool_use")
	case "s4-a-renumbered": // tool removed, later block renumbered, stop rewritten
		aText(w, 0, "Let me look.")
		aText(w, 1, "Done.")
		aEnd(w, "end_turn")
	case "s4-a-gap": // tool removed, index gap left (0, 2), stop rewritten
		aText(w, 0, "Let me look.")
		aText(w, 2, "Done.")
		aEnd(w, "end_turn")
	case "s4-a-stop-stale": // tool removed but stop_reason still tool_use
		aText(w, 0, "Let me look.")
		aEnd(w, "tool_use")
	case "s4-a-error": // error event mid-stream (what the watchdog sends)
		sse(w, "content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		sse(w, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me"}}`)
		sse(w, "error", `{"type":"error","error":{"type":"api_error","message":"blocked by egress policy"}}`)
	default:
		aEnd(w, "end_turn")
	}
	return true
}

// --- OpenAI Chat Completions ----------------------------------------------

func oChunk(w http.ResponseWriter, model, delta, finish string) {
	f := "null"
	if finish != "" {
		f = fmt.Sprintf("%q", finish)
	}
	sse(w, "", fmt.Sprintf(`{"id":"chatcmpl-s4","object":"chat.completion.chunk","created":1730000000,"model":%q,"choices":[{"index":0,"delta":%s,"finish_reason":%s}]}`, model, delta, f))
}

func oTool(w http.ResponseWriter, model string, idx int, id string) {
	oChunk(w, model, fmt.Sprintf(`{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":"bash","arguments":""}}]}`, idx, id), "")
	oChunk(w, model, fmt.Sprintf(`{"tool_calls":[{"index":%d,"function":{"arguments":"{\"cmd\": \"ls\"}"}}]}`, idx), "")
}

func chatScenario(w http.ResponseWriter, model string) {
	w.Header().Set("content-type", "text/event-stream")
	oChunk(w, model, `{"role":"assistant","content":""}`, "")
	switch model {
	case "s4-o-baseline": // two tool calls, index 0 and 1
		oTool(w, model, 0, "call_a")
		oTool(w, model, 1, "call_b")
		oChunk(w, model, `{}`, "tool_calls")
	case "s4-o-gap": // call 0 removed, call 1 keeps its index
		oTool(w, model, 1, "call_b")
		oChunk(w, model, `{}`, "tool_calls")
	case "s4-o-renumbered": // call 0 removed, call 1 renumbered to 0
		oTool(w, model, 0, "call_b")
		oChunk(w, model, `{}`, "tool_calls")
	case "s4-o-finish-rewritten": // all calls removed, text instead, finish stop
		oChunk(w, model, `{"content":"I can't run that here."}`, "")
		oChunk(w, model, `{}`, "stop")
	case "s4-o-error": // error object mid-stream
		oChunk(w, model, `{"content":"Let me"}`, "")
		sse(w, "", `{"error":{"message":"blocked by egress policy","type":"server_error","code":null,"param":null}}`)
		return
	default:
		oChunk(w, model, `{"content":"hello"}`, "stop")
	}
	sse(w, "", "[DONE]")
}

// --- OpenAI Responses -----------------------------------------------------

func rEv(w http.ResponseWriter, seq *int, typ, body string) {
	sse(w, typ, fmt.Sprintf(`{"type":%q,"sequence_number":%d,%s}`, typ, *seq, body))
	*seq++
}

func rResponse(model, status, output string) string {
	return fmt.Sprintf(`{"id":"resp_s4","object":"response","created_at":1730000000,"model":%q,"status":%q,"output":[%s],"parallel_tool_calls":true,"tool_choice":"auto","tools":[]}`, model, status, output)
}

const rMsgItem = `{"id":"msg_s4","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Done.","annotations":[]}]}`

func rFuncItem(status string) string {
	return fmt.Sprintf(`{"id":"fc_s4","type":"function_call","call_id":"call_s4","name":"bash","arguments":"{\"cmd\": \"ls\"}","status":%q}`, status)
}

func rText(w http.ResponseWriter, seq *int, outIdx int) {
	rEv(w, seq, "response.output_item.added", fmt.Sprintf(`"output_index":%d,"item":{"id":"msg_s4","type":"message","role":"assistant","status":"in_progress","content":[]}`, outIdx))
	rEv(w, seq, "response.content_part.added", fmt.Sprintf(`"item_id":"msg_s4","output_index":%d,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}`, outIdx))
	rEv(w, seq, "response.output_text.delta", fmt.Sprintf(`"item_id":"msg_s4","output_index":%d,"content_index":0,"delta":"Done."`, outIdx))
	rEv(w, seq, "response.output_text.done", fmt.Sprintf(`"item_id":"msg_s4","output_index":%d,"content_index":0,"text":"Done."`, outIdx))
	rEv(w, seq, "response.content_part.done", fmt.Sprintf(`"item_id":"msg_s4","output_index":%d,"content_index":0,"part":{"type":"output_text","text":"Done.","annotations":[]}`, outIdx))
	rEv(w, seq, "response.output_item.done", fmt.Sprintf(`"output_index":%d,"item":%s`, outIdx, rMsgItem))
}

func rFunc(w http.ResponseWriter, seq *int, outIdx int) {
	rEv(w, seq, "response.output_item.added", fmt.Sprintf(`"output_index":%d,"item":%s`, outIdx, rFuncItem("in_progress")))
	rEv(w, seq, "response.function_call_arguments.delta", fmt.Sprintf(`"item_id":"fc_s4","output_index":%d,"delta":"{\"cmd\": \"ls\"}"`, outIdx))
	rEv(w, seq, "response.function_call_arguments.done", fmt.Sprintf(`"item_id":"fc_s4","output_index":%d,"arguments":"{\"cmd\": \"ls\"}"`, outIdx))
	rEv(w, seq, "response.output_item.done", fmt.Sprintf(`"output_index":%d,"item":%s`, outIdx, rFuncItem("completed")))
}

func responsesScenario(w http.ResponseWriter, model string) {
	w.Header().Set("content-type", "text/event-stream")
	seq := 0
	rEv(w, &seq, "response.created", `"response":`+rResponse(model, "in_progress", ""))
	rEv(w, &seq, "response.in_progress", `"response":`+rResponse(model, "in_progress", ""))
	switch model {
	case "s4-r-baseline": // function call (0) then message (1)
		rFunc(w, &seq, 0)
		rText(w, &seq, 1)
		rEv(w, &seq, "response.completed", `"response":`+rResponse(model, "completed", rFuncItem("completed")+","+rMsgItem))
	case "s4-r-seq-gap": // function call removed: sequence_number jumps, message keeps output_index 1
		seq += 4
		rText(w, &seq, 1)
		rEv(w, &seq, "response.completed", `"response":`+rResponse(model, "completed", rMsgItem))
	case "s4-r-renumbered": // function call removed, sequence and output_index renumbered
		rText(w, &seq, 0)
		rEv(w, &seq, "response.completed", `"response":`+rResponse(model, "completed", rMsgItem))
	case "s4-r-failed": // ends with response.failed
		rFunc(w, &seq, 0)
		rEv(w, &seq, "response.failed", `"response":{"id":"resp_s4","object":"response","created_at":1730000000,"model":"`+model+`","status":"failed","output":[],"error":{"code":"server_error","message":"blocked by egress policy"},"parallel_tool_calls":true,"tool_choice":"auto","tools":[]}`)
	default:
		rText(w, &seq, 0)
		rEv(w, &seq, "response.completed", `"response":`+rResponse(model, "completed", rMsgItem))
	}
}
