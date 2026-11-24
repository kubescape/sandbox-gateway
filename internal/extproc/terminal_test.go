package extproc

import (
	"context"
	"strings"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/kubescape/sandbox-gateway/internal/sse"
	"github.com/kubescape/sandbox-gateway/internal/streamfmt"
)

// Review: the early-EOS fault ends each stream in its own format. Open
// Responses items must not be closed with Anthropic content_block_stop events,
// and an OpenAI stream must not get Anthropic events at all.
func TestTerminalEventsPerFormat(t *testing.T) {
	for _, tc := range []struct {
		name, first, stop string
		want              []string
	}{
		{"anthropic", `{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`, "end_turn",
			[]string{`"type":"content_block_stop","index":2`, "message_stop"}},
		{"openai chat", `{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`, "stop",
			[]string{`"finish_reason":"stop"`, "data: [DONE]\n\n"}},
		{"openai responses", `{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"type":"message"}}`, "incomplete",
			[]string{"event: response.incomplete\n"}},
	} {
		tx := &txn{}
		tx.trackEvent(sse.Event{Data: tc.first})
		b, stop := tx.terminalEvents()
		got := string(b)
		if stop != tc.stop {
			t.Errorf("%s: stop = %q, want %q", tc.name, stop, tc.stop)
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", tc.name, w, got)
			}
		}
		if tx.track.Format != streamfmt.Anthropic && strings.Contains(got, "message_stop") {
			t.Errorf("%s: Anthropic events in another format:\n%s", tc.name, got)
		}
		// What the fault sends parses back as the end of the same format.
		var tr streamfmt.Tracker
		var p sse.Parser
		for _, ev := range p.Feed(b) {
			tr.Event(ev)
		}
		if !tr.Done || tr.StopReason != tc.stop {
			t.Errorf("%s: terminal events read back as done=%v stop=%q", tc.name, tr.Done, tr.StopReason)
		}
	}
}

// Review: a response that ends in trailers has no body chunk marked end of
// stream. Its last event, ended by a lone CR, must still be tracked.
func TestTrailersCloseTheParser(t *testing.T) {
	h := newHarness(t, Faults{})
	st, err := h.client.Process(context.Background())
	must(t, err)
	sendRequest(t, st)
	body := "event: message_start\rdata: {\"type\":\"message_start\"}\r\r" +
		"event: message_delta\rdata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"}}\r\r"
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
		ResponseBody: &extprocv3.HttpBody{Body: []byte(body)}}}))
	recv(t, st)
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
		ResponseTrailers: &extprocv3.HttpTrailers{}}}))
	recv(t, st)
	must(t, st.CloseSend())
	if r := h.waitRecords(t, 1)[0]; r.StopReason != "max_tokens" || r.SSEEvents != 2 || r.Ended != "trailers" {
		t.Fatalf("record: stop=%q events=%d ended=%q", r.StopReason, r.SSEEvents, r.Ended)
	}
}
