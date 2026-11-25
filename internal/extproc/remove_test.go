package extproc

import (
	"strings"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/kubescape/sandbox-gateway/internal/renumber"
	"github.com/kubescape/sandbox-gateway/internal/streamfmt"
)

func removeTools() renumber.Filter {
	return func(it streamfmt.Item) bool { return it.Kind == "tool_use" }
}

// textToolText is an Anthropic stream: text 0, tool 1, text 2, ending in
// tool_use.
var textToolText = []string{
	"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\"}}\n\n",
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"bash\",\"input\":{}}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n",
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
}

func TestRemoveRenumbersTheForwardedStream(t *testing.T) {
	_, h := start(t, Config{Remove: removeTools})
	st := h.stream(t)
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	recv(t, st)
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: hdrs(":status", "200", "content-type", "text/event-stream")}}}))
	recv(t, st)
	var out strings.Builder
	for i, c := range textToolText {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(c), EndOfStream: i == len(textToolText)-1}}}))
		out.WriteString(string(recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse().GetBody()))
	}
	must(t, st.CloseSend())
	got := out.String()
	if strings.Contains(got, "tool_use\",\"id") || strings.Contains(got, `"index":2`) {
		t.Fatalf("tool not removed or index not renumbered:\n%s", got)
	}
	if strings.Count(got, `"index":1`) != 2 || !strings.Contains(got, `"stop_reason":"tool_use"`) {
		t.Fatalf("second text block not at index 1, or stop reason changed:\n%s", got)
	}
	// The record counts the stream the provider sent.
	if r := h.waitRecords(t, 1)[0]; r.SSEEvents != 9 || r.StopReason != "tool_use" {
		t.Fatalf("record: events %d stop %q", r.SSEEvents, r.StopReason)
	}
}

// Review: a response that ends in trailers, whose last event is ended by lone
// CRs, has that event forwarded before the trailers, not dropped in the editor.
func TestRemoveFlushesBeforeTrailers(t *testing.T) {
	_, h := start(t, Config{Remove: removeTools})
	st := h.stream(t)
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	recv(t, st)
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: hdrs(":status", "200", "content-type", "text/event-stream")}}}))
	recv(t, st)
	chunks := append([]string(nil), textToolText[:4]...)
	chunks = append(chunks, "event: message_delta\rdata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\r\revent: message_stop\rdata: {\"type\":\"message_stop\"}\r\r")
	var out strings.Builder
	for _, c := range chunks {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(c)}}}))
		out.WriteString(string(recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse().GetBody()))
	}
	sendTrailersResp(t, st)
	flush := recv(t, st)
	sr := flush.GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
	if sr == nil {
		t.Fatalf("no body before the trailers: %v; forwarded so far: %q", flush, out.String())
	}
	out.Write(sr.GetBody())
	if r := recv(t, st); r.GetResponseTrailers() == nil {
		t.Fatalf("after the flush, want the trailers answer: %v", r)
	}
	must(t, st.CloseSend())
	if got := out.String(); !strings.Contains(got, `{"type":"message_stop"}`) || strings.Contains(got, `"index":2`) {
		t.Fatalf("message_stop lost or stream not renumbered:\n%q", got)
	}
}

func sendTrailersResp(t *testing.T, st extprocv3.ExternalProcessor_ProcessClient) {
	t.Helper()
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
		ResponseTrailers: &extprocv3.HttpTrailers{}}}))
}
