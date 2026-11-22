package extproc

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kubescape/sandbox-gateway/internal/sse"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

const reqBody = `{"model":"claude-opus-5-5","stream":true,"max_tokens":64,"tools":[{"name":"bash"}],"messages":[{"role":"user","content":"hi"}]}`

var respSSE = []string{
	"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\nevent: content_",
	"block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}\n\n",
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
}

// fakeEvaluator is a test evaluator. It returns a canned decision and keeps the
// body it was fed, so the tests cover the framework's side of the seam and no
// rule logic.
type fakeEvaluator struct {
	mu       sync.Mutex
	decision plugin.Decision
	fed      []byte
}

const fakeRuleID = "test.canned-decision"

func wouldDeny() *fakeEvaluator {
	return &fakeEvaluator{decision: plugin.Decision{RuleID: fakeRuleID, Action: plugin.WouldDeny,
		Reason: "canned", Model: "claude-opus-5-5", Stream: true, Tools: []string{"bash"}, Messages: 1}}
}

func (f *fakeEvaluator) Inspects(path string) bool { return path == "/v1/messages" }
func (f *fakeEvaluator) NewScan() plugin.Scan      { return f }

func (f *fakeEvaluator) Feed(chunk []byte) {
	f.mu.Lock()
	f.fed = append(f.fed, chunk...)
	f.mu.Unlock()
}

func (f *fakeEvaluator) Decide() plugin.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decision
}

func (f *fakeEvaluator) body() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.fed)
}

type harness struct {
	eval    *fakeEvaluator
	client  extprocv3.ExternalProcessorClient
	mu      sync.Mutex
	records []Record
}

func newHarness(t *testing.T, faults Faults) *harness {
	return newHarnessBudget(t, faults, 0)
}

func newHarnessBudget(t *testing.T, faults Faults, budget time.Duration) *harness {
	t.Helper()
	h := &harness{eval: wouldDeny()}
	srv := New(Config{
		Evaluator:   h.eval,
		Faults:      faults,
		ChunkBudget: budget,
		Emit: func(r Record) {
			h.mu.Lock()
			h.records = append(h.records, r)
			h.mu.Unlock()
		},
	})
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///buf",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	h.client = extprocv3.NewExternalProcessorClient(conn)
	return h
}

func (h *harness) waitRecords(t *testing.T, n int) []Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		if len(h.records) >= n {
			r := append([]Record(nil), h.records...)
			h.mu.Unlock()
			return r
		}
		h.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no record after 3s")
	return nil
}

func hdrs(kv ...string) *corev3.HeaderMap {
	m := &corev3.HeaderMap{}
	for i := 0; i < len(kv); i += 2 {
		m.Headers = append(m.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return m
}

func attrMeta() *corev3.Metadata {
	s, _ := structpb.NewStruct(map[string]any{"pod_uid": "uid-1", "pid": "4242"})
	return &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{AttributionNS: s}}
}

// sendRequest drives the request half and returns the response to the last body chunk.
func sendRequest(t *testing.T, st extprocv3.ExternalProcessor_ProcessClient) *extprocv3.ProcessingResponse {
	t.Helper()
	must(t, st.Send(&extprocv3.ProcessingRequest{
		MetadataContext: attrMeta(),
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: hdrs(":method", "POST", ":path", "/v1/messages", ":authority", "api.anthropic.com", "x-request-id", "rid-1")}}}))
	recv(t, st)
	half := len(reqBody) / 2
	var last *extprocv3.ProcessingResponse
	var echoed []byte
	for i, part := range []string{reqBody[:half], reqBody[half:]} {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: []byte(part), EndOfStream: i == 1}}}))
		last = recv(t, st)
		echoed = append(echoed, last.GetRequestBody().GetResponse().GetBodyMutation().GetStreamedResponse().GetBody()...)
	}
	if string(echoed) != reqBody {
		t.Fatalf("request body not forwarded unchanged:\n%s", echoed)
	}
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: hdrs(":status", "200", "content-type", "text/event-stream")}}}))
	recv(t, st)
	return last
}

func TestAuditPassThrough(t *testing.T) {
	h := newHarness(t, Faults{})
	st, err := h.client.Process(context.Background())
	must(t, err)
	last := sendRequest(t, st)

	audit := last.GetDynamicMetadata().GetFields()[AuditNS].GetStructValue().GetFields()
	if audit["action"].GetStringValue() != "would_deny" || audit["rule_id"].GetStringValue() != fakeRuleID {
		t.Fatalf("audit metadata = %v", audit)
	}
	if got := h.eval.body(); got != reqBody {
		t.Fatalf("evaluator was fed %q", got)
	}

	var out []byte
	for i, c := range respSSE {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(c), EndOfStream: i == len(respSSE)-1}}}))
		sr := recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
		out = append(out, sr.GetBody()...)
		if sr.GetEndOfStream() != (i == len(respSSE)-1) {
			t.Fatalf("chunk %d eos=%v", i, sr.GetEndOfStream())
		}
	}
	if string(out) != strings.Join(respSSE, "") {
		t.Fatal("response not forwarded unchanged")
	}
	must(t, st.CloseSend())

	r := h.waitRecords(t, 1)[0]
	if r.TransactionID != "rid-1" || r.Attribution["pod_uid"] != "uid-1" || r.Attribution["pid"] != "4242" {
		t.Fatalf("identity: %+v", r)
	}
	if r.Decision == nil || r.Decision.Action != plugin.WouldDeny || len(r.Decision.Tools) != 1 {
		t.Fatalf("decision: %+v", r.Decision)
	}
	if r.SSEEvents != 7 || r.StopReason != "end_turn" || r.Status != "200" || r.Ended != "eos" || r.EarlyEOS {
		t.Fatalf("record: %+v", r)
	}
}

func TestEarlyEOSClosesTurn(t *testing.T) {
	h := newHarness(t, Faults{EarlyEOSAfterEvents: 3})
	st, err := h.client.Process(context.Background())
	must(t, err)
	sendRequest(t, st)

	var out []byte
	var sawEOS bool
	for i, c := range respSSE {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(c), EndOfStream: i == len(respSSE)-1}}}))
		sr := recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
		if sawEOS && len(sr.GetBody()) > 0 {
			t.Fatal("bytes forwarded after early EOS")
		}
		out = append(out, sr.GetBody()...)
		sawEOS = sawEOS || sr.GetEndOfStream()
	}
	if !sawEOS {
		t.Fatal("no early EOS")
	}

	// What the client receives must be a well-formed Anthropic stream that
	// closes the open block and ends with message_stop.
	var p sse.Parser
	evs := p.Feed(out)
	if p.Pending() != 0 {
		t.Fatalf("client got a partial event: %q", out[len(out)-p.Pending():])
	}
	var names []string
	for _, e := range evs {
		names = append(names, e.Name)
	}
	want := "message_start content_block_start content_block_delta content_block_stop message_delta message_stop"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("client events:\n got %s\nwant %s", got, want)
	}
	must(t, st.CloseSend())
	if r := h.waitRecords(t, 1)[0]; !r.EarlyEOS || r.StopReason != "end_turn" {
		t.Fatalf("record: %+v", r)
	}
}

// The trigger event sits in the middle of a chunk: nothing after it may reach the client.
func TestEarlyEOSCutsMidChunk(t *testing.T) {
	h := newHarness(t, Faults{EarlyEOSAfterEvents: 2})
	st, err := h.client.Process(context.Background())
	must(t, err)
	sendRequest(t, st)
	var out []byte
	for i := 0; i < 2; i++ {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(respSSE[i])}}}))
		out = append(out, recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse().GetBody()...)
	}
	var p sse.Parser
	var names []string
	for _, e := range p.Feed(out) {
		names = append(names, e.Name)
	}
	want := "message_start content_block_start content_block_stop message_delta message_stop"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("client events:\n got %s\nwant %s", got, want)
	}
	if p.Pending() != 0 {
		t.Fatal("client got a partial event")
	}
	must(t, st.CloseSend())
}

// Identity from the PPv2 TLVs is copied into kubescape.sandbox.audit so the access log can show it.
func TestAttributionEchoedToAuditMetadata(t *testing.T) {
	h := newHarness(t, Faults{})
	st, err := h.client.Process(context.Background())
	must(t, err)
	last := sendRequest(t, st)
	audit := last.GetDynamicMetadata().GetFields()[AuditNS].GetStructValue().GetFields()
	if audit["pod_uid"].GetStringValue() != "uid-1" || audit["pid"].GetStringValue() != "4242" {
		t.Fatalf("audit metadata = %v", audit)
	}
	must(t, st.CloseSend())
}

// AC6: a stalled chunk is ended fail-closed with an error event within the budget.
func TestWatchdogEndsStalledResponse(t *testing.T) {
	h := newHarnessBudget(t, Faults{StallAfterChunks: 1}, 200*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := h.client.Process(ctx)
	must(t, err)
	sendRequest(t, st)
	for i := 0; i < 2; i++ {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(respSSE[i])}}}))
	}
	recv(t, st) // first chunk answered normally
	start := time.Now()
	sr := recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
	took := time.Since(start)
	if !sr.GetEndOfStream() || !strings.Contains(string(sr.GetBody()), "event: error") {
		t.Fatalf("watchdog response: eos=%v body=%q", sr.GetEndOfStream(), sr.GetBody())
	}
	if took > time.Second {
		t.Fatalf("watchdog took %v", took)
	}
	cancel()
	if r := h.waitRecords(t, 1)[0]; !r.WatchdogFired || r.Ended != "watchdog" {
		t.Fatalf("record: %+v", r)
	}
}

// The watchdog stays quiet on a healthy stream.
func TestWatchdogQuietWhenHealthy(t *testing.T) {
	h := newHarnessBudget(t, Faults{}, 200*time.Millisecond)
	st, err := h.client.Process(context.Background())
	must(t, err)
	sendRequest(t, st)
	for i, c := range respSSE {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(c), EndOfStream: i == len(respSSE)-1}}}))
		recv(t, st)
		time.Sleep(300 * time.Millisecond) // gaps between chunks are not processing time
	}
	must(t, st.CloseSend())
	if r := h.waitRecords(t, 1)[0]; r.WatchdogFired || r.Ended != "eos" {
		t.Fatalf("record: %+v", r)
	}
}

func TestStallFaultBlocksUntilCancel(t *testing.T) {
	h := newHarness(t, Faults{StallAfterChunks: 1})
	ctx, cancel := context.WithCancel(context.Background())
	st, err := h.client.Process(ctx)
	must(t, err)
	sendRequest(t, st)
	for i := 0; i < 2; i++ {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(respSSE[i])}}}))
	}
	recv(t, st) // first chunk answered
	got := make(chan error, 1)
	go func() { _, err := st.Recv(); got <- err }()
	select {
	case <-got:
		t.Fatal("second chunk answered; processor did not stall")
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	if r := h.waitRecords(t, 1)[0]; r.Ended != "stream_error" || r.ResponseChunks != 2 {
		t.Fatalf("record: %+v", r)
	}
}

func recv(t *testing.T, st extprocv3.ExternalProcessor_ProcessClient) *extprocv3.ProcessingResponse {
	t.Helper()
	r, err := st.Recv()
	must(t, err)
	return r
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The evaluator's document version and degraded flag reach the audit metadata.
func TestDecisionVersionAndDegradedReachAudit(t *testing.T) {
	eval := &fakeEvaluator{decision: plugin.Decision{RuleID: fakeRuleID, Action: plugin.Allow, ClassVersion: "v7"}}
	h := &harness{}
	srv := New(Config{Evaluator: eval, Emit: func(r Record) {
		h.mu.Lock()
		h.records = append(h.records, r)
		h.mu.Unlock()
	}})
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	go g.Serve(lis)
	defer g.Stop()
	conn, _ := grpc.NewClient("passthrough:///buf",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	h.client = extprocv3.NewExternalProcessorClient(conn)

	for i, degraded := range []bool{false, true} {
		eval.mu.Lock()
		eval.decision.Degraded = degraded
		eval.mu.Unlock()
		st, err := h.client.Process(context.Background())
		must(t, err)
		last := sendRequest(t, st)
		must(t, st.CloseSend())
		a := last.GetDynamicMetadata().GetFields()[AuditNS].GetStructValue().GetFields()
		if a["action"].GetStringValue() != "allow" || a["class_version"].GetStringValue() != "v7" || a["degraded"].GetBoolValue() != degraded {
			t.Fatalf("run %d: %v", i, a)
		}
	}
}

// Enforce: a would_deny request gets a 403 instead of its last chunk being forwarded.
func TestEnforceBlocksWithProviderShaped403(t *testing.T) {
	h := &harness{}
	srv := New(Config{Evaluator: wouldDeny(), Enforce: true, Emit: func(r Record) {
		h.mu.Lock()
		h.records = append(h.records, r)
		h.mu.Unlock()
	}})
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	go g.Serve(lis)
	defer g.Stop()
	conn, _ := grpc.NewClient("passthrough:///buf",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	st, err := extprocv3.NewExternalProcessorClient(conn).Process(context.Background())
	must(t, err)
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
		Headers: hdrs(":method", "POST", ":path", "/v1/messages", ":authority", "api.anthropic.com")}}}))
	recv(t, st)
	half := len(reqBody) / 2
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{RequestBody: &extprocv3.HttpBody{Body: []byte(reqBody[:half])}}}))
	recv(t, st) // first chunk forwarded
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{RequestBody: &extprocv3.HttpBody{Body: []byte(reqBody[half:]), EndOfStream: true}}}))
	ir := recv(t, st).GetImmediateResponse()
	if ir == nil || ir.GetStatus().GetCode() != 403 || !strings.Contains(string(ir.GetBody()), "permission_error") {
		t.Fatalf("immediate response = %v", ir)
	}
	must(t, st.CloseSend())
	if r := h.waitRecords(t, 1)[0]; r.Decision.Action != plugin.Deny || r.Ended != "denied" {
		t.Fatalf("record: %+v", r)
	}
}
