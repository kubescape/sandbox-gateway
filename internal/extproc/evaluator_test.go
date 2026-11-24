package extproc

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

const testBudget = 200 * time.Millisecond

func auditFields(r *extprocv3.ProcessingResponse) map[string]string {
	out := map[string]string{}
	for k, v := range r.GetDynamicMetadata().GetFields()[AuditNS].GetStructValue().GetFields() {
		switch {
		case v.GetStringValue() != "":
			out[k] = v.GetStringValue()
		case v.GetBoolValue():
			out[k] = "true"
		}
	}
	return out
}

func allowPodTable() *fakeTable {
	tb := newTable()
	tb.bindings[testCgroup] = conntable.Binding{BindingID: 12, Posture: conntable.PostureAllow}
	return tb
}

func immediateBody(r *extprocv3.ProcessingResponse) string {
	return string(r.GetImmediateResponse().GetBody())
}

const frameworkBody = `{"error":{"type":"gateway_error","message":"request blocked by the gateway"}}`

// ---- Task 4.2 ----

func TestClassifySeesWholeBody(t *testing.T) {
	st, h := start(t, Config{Evaluator: allowAll()})
	sendHeaders(t, st)
	third := len(reqBody) / 3
	sendBody(t, st, reqBody[:third], false) // held: no answer yet
	sendBody(t, st, reqBody[third:2*third], false)
	if got := forwarded(recv(t, st)); got != reqBody[:third] {
		t.Fatalf("forwarded %q, want the first chunk", got)
	}
	sendBody(t, st, reqBody[2*third:], true)
	if got := forwarded(recv(t, st)); got != reqBody[third:] {
		t.Fatalf("forwarded %q at the end", got)
	}
	if got := h.eval.body(); got != reqBody {
		t.Fatalf("Classify read %q", got)
	}
}

func TestRequestReachesEvaluator(t *testing.T) {
	st, h := start(t, Config{Evaluator: allowAll()})
	sendHeaders(t, st, "x-custom", "one", "content-type", "application/json")
	sendBody(t, st, reqBody, true)
	recv(t, st)
	r := h.eval.lastRequest()
	if r.Host != "api.anthropic.com" || r.Method != "POST" || r.Path != "/v1/messages" ||
		r.Model != "claude-opus-5-5" || !r.HasModel || r.Degraded || len(r.Sections) != 0 {
		t.Fatalf("request = %+v", r)
	}
	if r.Headers.Get("X-Custom") != "one" || r.Headers.Get(":path") != "" {
		t.Fatalf("headers = %v", r.Headers)
	}
	want := plugin.Workload{Namespace: "agents", Pod: "coder-7d9f", Container: "main",
		ControllerKind: "Deployment", ControllerName: "coder", BindingID: 12, Posture: "deny",
		Policies: []plugin.PolicyRef{{UID: "uid-a", Generation: 4}}}
	if !reflect.DeepEqual(r.Workload, want) {
		t.Fatalf("workload = %+v", r.Workload)
	}
}

func TestEnforceDenyUsesDenyResponse(t *testing.T) {
	st, h := start(t, Config{Evaluator: enforceDeny()})
	sendHeaders(t, st)
	half := len(reqBody) / 2
	sendBody(t, st, reqBody[:half], false)
	sendBody(t, st, reqBody[half:], true)
	r := recv(t, st) // the first answer is the block: no chunk was forwarded
	ir := r.GetImmediateResponse()
	if ir.GetStatus().GetCode() != 403 || immediateBody(r) != fakeDenyBody(fakeRuleID) {
		t.Fatalf("response = %v", r)
	}
	var fake string
	for _, hv := range ir.GetHeaders().GetSetHeaders() {
		if hv.GetHeader().GetKey() == "x-fake" {
			fake = string(hv.GetHeader().GetRawValue())
		}
	}
	if fake != "anthropic" {
		t.Fatalf("headers did not come from DenyResponse: %v", ir.GetHeaders())
	}
	must(t, st.CloseSend())
	rec := h.waitRecords(t, 1)[0]
	if rec.Ended != "denied" || rec.Verdict.Rule != fakeRuleID || rec.WouldDeny {
		t.Fatalf("record: %+v", rec)
	}
}

func TestAuditDenyPasses(t *testing.T) {
	st, h := start(t, Config{Evaluator: auditDeny()})
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	r := recv(t, st)
	if forwarded(r) != reqBody || r.GetImmediateResponse() != nil {
		t.Fatalf("response = %v", r)
	}
	if a := auditFields(r); a["would_deny"] != "true" || a["mode"] != "audit" {
		t.Fatalf("audit = %v", a)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; !rec.WouldDeny || rec.Ended == "denied" {
		t.Fatalf("record: %+v", rec)
	}
}

func TestNoBodyStillDecided(t *testing.T) {
	st, h := start(t, Config{Evaluator: enforceDeny()})
	must(t, st.Send(&extprocv3.ProcessingRequest{Attributes: srcAttrs(testSource),
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: hdrs(":method", "GET", ":path", "/v1/models", ":authority", "api.anthropic.com"), EndOfStream: true}}}))
	if r := recv(t, st); !is403(r) {
		t.Fatalf("want a 403 at the headers, got %v", r)
	}
	if c, e, _, _ := h.eval.counts(); c != 1 || e != 1 {
		t.Fatalf("classify %d, evaluate %d", c, e)
	}
}

func TestTrailersStillDecided(t *testing.T) {
	st, _ := start(t, Config{Evaluator: enforceDeny()})
	sendHeaders(t, st)
	sendBody(t, st, reqBody, false) // held
	sendTrailers(t, st)
	if r := recv(t, st); !is403(r) {
		t.Fatalf("want 403 on the trailers, got %v", r)
	}

	// Allowed: the held chunk goes first, then the trailers answer.
	st, _ = start(t, Config{Evaluator: allowAll()})
	sendHeaders(t, st)
	sendBody(t, st, reqBody, false)
	sendTrailers(t, st)
	if got := forwarded(recv(t, st)); got != reqBody {
		t.Fatalf("held chunk: %q", got)
	}
	if r := recv(t, st); r.GetRequestTrailers() == nil {
		t.Fatalf("want the trailers answer, got %v", r)
	}
}

func TestWebSocketUpgradeDecidedOnHeaders(t *testing.T) {
	st, _ := start(t, Config{Evaluator: enforceDeny()})
	if r := sendHeaders(t, st, "upgrade", "websocket"); !is403(r) {
		t.Fatalf("want 403 at the headers, got %v", r)
	}

	st, h := start(t, Config{Evaluator: allowAll()})
	if r := sendHeaders(t, st, "upgrade", "websocket"); r.GetRequestHeaders() == nil {
		t.Fatalf("allowed upgrade: %v", r)
	}
	sendBody(t, st, "\x81\x05hello", false) // a frame
	if got := forwarded(recv(t, st)); got != "\x81\x05hello" {
		t.Fatalf("frame: %q", got)
	}
	if c, e, _, _ := h.eval.counts(); c != 1 || e != 1 || h.eval.body() != "" {
		t.Fatalf("classify %d, evaluate %d, fed %q", c, e, h.eval.body())
	}
}

func TestNoEvaluatorPassesEverything(t *testing.T) {
	st, h := start(t, Config{})
	sendHeaders(t, st)
	half := len(reqBody) / 2
	sendBody(t, st, reqBody[:half], false)
	if got := forwarded(recv(t, st)); got != reqBody[:half] {
		t.Fatalf("held without an evaluator: %q", got)
	}
	sendBody(t, st, reqBody[half:], true)
	r := recv(t, st)
	if forwarded(r) != reqBody[half:] || r.GetImmediateResponse() != nil {
		t.Fatalf("response = %v", r)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; rec.Verdict != nil || rec.Degraded {
		t.Fatalf("record: %+v", rec)
	}
}

// Review focus: Classify stops reading. The write of the next chunk is
// bounded, the writer returns, and the request is refused.
func TestClassifyStallBounded(t *testing.T) {
	stall := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(stall) }) }
	t.Cleanup(free)
	f := allowAll()
	f.classifyHook = func(body io.Reader) {
		_, _ = body.Read(make([]byte, 64<<10)) // the first chunk
		<-stall                                // then never reads again
	}
	st, h := start(t, Config{Evaluator: f, ChunkBudget: testBudget})
	sendHeaders(t, st)
	half := len(reqBody) / 2
	sendBody(t, st, reqBody[:half], false)
	begun := time.Now()
	sendBody(t, st, reqBody[half:], false)
	r := recv(t, st)
	if took := time.Since(begun); took > testBudget+callbackBudget+300*time.Millisecond {
		t.Fatalf("took %v", took)
	}
	if !is403(r) || immediateBody(r) != fakeDenyBody(RuleEvaluatorTimeout) {
		t.Fatalf("response = %v", r)
	}
	waitIdle(t, h.srv, 1) // the stalled Classify is stuck; no writer is left
	// Review: the stalled Classify holds a slot, so it is counted as stuck
	// from the timeout until it returns.
	if n := h.srv.StuckEvaluatorCalls(); n != 1 {
		t.Fatalf("stuck = %d at the timeout, want 1", n)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; !strings.HasPrefix(rec.EvaluatorError, "classify: ") || rec.Verdict.Rule != RuleEvaluatorTimeout {
		t.Fatalf("record: %+v", rec)
	}
	free()
	waitIdle(t, h.srv, 0)
	if n := h.srv.StuckEvaluatorCalls(); n != 0 {
		t.Fatalf("stuck = %d after Classify returned, want 0", n)
	}
}

// Review: Evaluate's context ends at the budget, not when the stream does, so
// an evaluator that honours its context gives its slot back in time.
func TestEvaluateContextEndsAtBudget(t *testing.T) {
	ended := make(chan error, 1)
	f := allowAll()
	f.evaluateHook = func(ctx context.Context) {
		<-ctx.Done()
		ended <- ctx.Err()
	}
	st, h := start(t, Config{Evaluator: f, ChunkBudget: testBudget})
	sendHeaders(t, st)
	begun := time.Now()
	sendBody(t, st, reqBody, true)
	select {
	case err := <-ended:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("context ended with %v, want the deadline", err)
		}
		if took := time.Since(begun); took > testBudget+300*time.Millisecond {
			t.Fatalf("context ended after %v", took)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Evaluate's context did not end while the stream stayed open")
	}
	recv(t, st)
	waitIdle(t, h.srv, 0) // the slot is back, the stream still open
	if n := h.srv.StuckEvaluatorCalls(); n != 0 {
		t.Fatalf("stuck = %d", n)
	}
	must(t, st.CloseSend())
}

// Every way a transaction ends leaves no goroutine of it behind.
func TestPipeClosedOnEveryExit(t *testing.T) {
	slowReader := func(body io.Reader) { // reads, slowly, until the pipe closes
		buf := make([]byte, 16)
		for {
			time.Sleep(testBudget)
			if _, err := body.Read(buf); err != nil {
				return
			}
		}
	}
	for _, exit := range []string{"verdict", "timeout", "client_reset", "closed_mid_body"} {
		t.Run(exit, func(t *testing.T) {
			f := allowAll()
			if exit == "timeout" {
				f.classifyHook = slowReader
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, h := start(t, Config{Evaluator: f, ChunkBudget: testBudget})
			st, err := h.client.Process(ctx)
			must(t, err)
			sendHeaders(t, st)
			switch exit {
			case "verdict":
				sendBody(t, st, reqBody, true)
				recv(t, st)
				must(t, st.CloseSend())
			case "timeout":
				sendBody(t, st, reqBody, false)
				sendBody(t, st, reqBody, false)
				if r := recv(t, st); !is403(r) {
					t.Fatalf("want 403, got %v", r)
				}
				must(t, st.CloseSend())
			case "client_reset":
				sendBody(t, st, reqBody[:10], false)
				time.Sleep(20 * time.Millisecond)
				cancel()
			case "closed_mid_body":
				sendBody(t, st, reqBody[:10], false)
				must(t, st.CloseSend())
			}
			h.waitRecords(t, 1)
			waitIdle(t, h.srv, 0)
		})
	}
}

// ---- Task 4.3 ----

func TestWatchdogEndsStallWithStreamError(t *testing.T) {
	h := newHarnessBudget(t, Faults{StallAfterChunks: 1}, testBudget)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := h.client.Process(ctx)
	must(t, err)
	sendRequest(t, st)
	for i := 0; i < 2; i++ {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(respSSE[i])}}}))
	}
	recv(t, st)
	begun := time.Now()
	sr := recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
	if string(sr.GetBody()) != fakeStreamError("anthropic", "watchdog") || !sr.GetEndOfStream() || time.Since(begun) > time.Second {
		t.Fatalf("eos=%v body=%q after %v", sr.GetEndOfStream(), sr.GetBody(), time.Since(begun))
	}
}

func TestWatchdogUnderFiveSecondsAtDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the default budget")
	}
	h := newHarnessBudget(t, Faults{StallAfterChunks: 1}, DefaultChunkBudget)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := h.client.Process(ctx)
	must(t, err)
	sendRequest(t, st)
	for i := 0; i < 2; i++ {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(respSSE[i])}}}))
	}
	recv(t, st)
	begun := time.Now()
	sr := recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
	if !sr.GetEndOfStream() || time.Since(begun) >= 5*time.Second {
		t.Fatalf("eos=%v after %v", sr.GetEndOfStream(), time.Since(begun))
	}
}

// stallResponse runs a request through and stalls its second response chunk.
func stallResponse(t *testing.T, cfg Config) *extprocv3.StreamedBodyResponse {
	t.Helper()
	cfg.Faults = Faults{StallAfterChunks: 1}
	cfg.ChunkBudget = testBudget
	_, h := start(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st, err := h.client.Process(ctx)
	must(t, err)
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	recv(t, st)
	for i := 0; i < 2; i++ {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(respSSE[i])}}}))
	}
	recv(t, st)
	return recv(t, st).GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
}

func TestWatchdogNoEvaluatorEndsStream(t *testing.T) {
	sr := stallResponse(t, Config{})
	if !sr.GetEndOfStream() || len(sr.GetBody()) != 0 {
		t.Fatalf("eos=%v body=%q", sr.GetEndOfStream(), sr.GetBody())
	}
}

func TestStalledStreamErrorEndsStream(t *testing.T) {
	stall := release(t)
	f := allowAll()
	f.streamErrHook = func() { <-stall }
	sr := stallResponse(t, Config{Evaluator: f})
	if !sr.GetEndOfStream() || len(sr.GetBody()) != 0 {
		t.Fatalf("eos=%v body=%q", sr.GetEndOfStream(), sr.GetBody())
	}
}

// Review focus 4: a slow or panicking Evaluate fails that request only.
func TestSlowEvaluateFailsRequest(t *testing.T) {
	stall := release(t)
	f := allowAll()
	f.evaluateHook = func(context.Context) { <-stall } // ignores its context
	testEvaluateFails(t, f, "evaluate: "+errTimeout.Error())
}

func TestEvaluatorPanicFailsRequest(t *testing.T) {
	f := allowAll()
	f.evaluateHook = func(context.Context) { panic("evaluator bug") }
	testEvaluateFails(t, f, "evaluate: "+errPanic.Error())
}

func testEvaluateFails(t *testing.T, f *fakeEval, wantErr string) {
	t.Helper()
	st, h := start(t, Config{Evaluator: f, ChunkBudget: testBudget})
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	r := recv(t, st)
	if !is403(r) || immediateBody(r) != fakeDenyBody(RuleEvaluatorTimeout) {
		t.Fatalf("response = %v", r)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; rec.EvaluatorError != wantErr || rec.Ended != "denied" {
		t.Fatalf("record: %+v", rec)
	}
	// The next request, on a new stream, is decided normally.
	f.set(func(f *fakeEval) { f.evaluateHook = nil })
	st = h.stream(t)
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	if r := recv(t, st); forwarded(r) != reqBody {
		t.Fatalf("second request: %v", r)
	}
}

// Decision 10: calls that never return pile up only to the cap. Past it a
// request is not sent to the evaluator and is decided by its fail posture.
func TestRepeatedEvaluatorTimeoutsCapCalls(t *testing.T) {
	stall := release(t)
	f := allowAll()
	f.evaluateHook = func(context.Context) { <-stall }
	st, h := start(t, Config{Evaluator: f, ChunkBudget: testBudget, MaxEvaluatorCalls: 2})
	run := func(st extprocv3.ExternalProcessor_ProcessClient) *extprocv3.ProcessingResponse {
		sendHeaders(t, st)
		sendBody(t, st, reqBody, true)
		return recv(t, st)
	}
	// 1: Evaluate stalls; DenyResponse still finds a slot.
	if r := run(st); immediateBody(r) != fakeDenyBody(RuleEvaluatorTimeout) {
		t.Fatalf("first: %v", r)
	}
	// 2: Evaluate stalls in the last slot; DenyResponse finds none, so the
	// framework answers.
	if r := run(h.stream(t)); immediateBody(r) != frameworkBody {
		t.Fatalf("second: %v", r)
	}
	if n := h.srv.StuckEvaluatorCalls(); n != 2 {
		t.Fatalf("stuck = %d", n)
	}
	// 3: no slot for Classify. The pod's posture is deny, so it is blocked,
	// degraded, without a call into the evaluator.
	st = h.stream(t)
	r := sendHeaders(t, st)
	if !is403(r) || immediateBody(r) != frameworkBody {
		t.Fatalf("third: %v", r)
	}
	if c, e, _, _ := f.counts(); c != 2 || e != 2 {
		t.Fatalf("classify %d, evaluate %d: the saturated request reached the evaluator", c, e)
	}
	recs := h.waitRecords(t, 3)
	if rec := recs[2]; !rec.Degraded || rec.Verdict.Rule != RuleEvaluatorSaturated {
		t.Fatalf("record: %+v", rec)
	}
}

// Decision 12: DenyResponse that stalls or panics gets the framework 403.
func TestStalledDenyResponseUsesFrameworkFallback(t *testing.T) {
	stall := release(t)
	f := enforceDeny()
	f.denyHook = func() { <-stall }
	testFrameworkFallback(t, f)
}

func TestPanickingDenyResponseUsesFrameworkFallback(t *testing.T) {
	f := enforceDeny()
	f.denyHook = func() { panic("deny bug") }
	testFrameworkFallback(t, f)
}

func testFrameworkFallback(t *testing.T, f *fakeEval) {
	t.Helper()
	st, h := start(t, Config{Evaluator: f, ChunkBudget: testBudget})
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	begun := time.Now()
	r := recv(t, st)
	if took := time.Since(begun); took > testBudget+callbackBudget {
		t.Fatalf("took %v", took)
	}
	if !is403(r) || immediateBody(r) != frameworkBody {
		t.Fatalf("response = %v", r)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; !strings.Contains(rec.EvaluatorError, "deny_response: ") || rec.Verdict.Rule != fakeRuleID {
		t.Fatalf("record: %+v", rec)
	}
}

// fillSlots takes every evaluator slot with a call that never returns.
func fillSlots(t *testing.T, s *Server) {
	t.Helper()
	stall := release(t)
	for {
		if _, err := begin(s.calls, context.Background(), func(context.Context) struct{} { <-stall; return struct{}{} }); err != nil {
			return
		}
	}
}

func TestSaturationAllowPodPasses(t *testing.T) {
	f := enforceDeny()
	st, h := start(t, Config{Evaluator: f, Conns: allowPodTable(), MaxEvaluatorCalls: 2})
	fillSlots(t, h.srv)
	r := sendHeaders(t, st)
	if r.GetRequestHeaders() == nil || auditFields(r)["degraded"] != "true" {
		t.Fatalf("headers: %v", r)
	}
	sendBody(t, st, reqBody[:10], false) // not held: nothing evaluates it
	if got := forwarded(recv(t, st)); got != reqBody[:10] {
		t.Fatalf("forwarded %q", got)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; !rec.Degraded || rec.Verdict != nil || rec.Ended == "denied" {
		t.Fatalf("record: %+v", rec)
	}
	if c, e, d, _ := f.counts(); c+e+d != 0 {
		t.Fatalf("the evaluator was called: classify %d, evaluate %d, deny %d", c, e, d)
	}
}

func TestSaturationDenyPodBlocked(t *testing.T) {
	f := allowAll()
	st, h := start(t, Config{Evaluator: f, MaxEvaluatorCalls: 2}) // newTable: posture deny
	fillSlots(t, h.srv)
	r := sendHeaders(t, st)
	if !is403(r) || immediateBody(r) != frameworkBody {
		t.Fatalf("headers: %v", r)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; !rec.Degraded || rec.Ended != "denied" || rec.Verdict.Rule != RuleEvaluatorSaturated {
		t.Fatalf("record: %+v", rec)
	}
	if c, e, d, _ := f.counts(); c+e+d != 0 {
		t.Fatalf("the evaluator was called: classify %d, evaluate %d, deny %d", c, e, d)
	}
}

// Review: a deny verdict, once given, stands. When DenyResponse finds no slot
// on an allow pod, the framework 403 goes out; the request does not pass by
// the fail posture.
func TestDenyVerdictKeptWhenDenyResponseSaturated(t *testing.T) {
	f := enforceDeny()
	st, h := start(t, Config{Evaluator: f, Conns: allowPodTable(), MaxEvaluatorCalls: 1})
	// While Evaluate holds the only slot, a sender waits on it; it takes the
	// slot the moment Evaluate returns, before DenyResponse could.
	f.set(func(f *fakeEval) {
		f.evaluateHook = func(context.Context) {
			go func() { h.srv.calls.slots <- struct{}{} }()
			time.Sleep(20 * time.Millisecond)
		}
	})
	t.Cleanup(func() { <-h.srv.calls.slots })
	sendHeaders(t, st)
	sendBody(t, st, reqBody, true)
	r := recv(t, st)
	if !is403(r) || immediateBody(r) != frameworkBody {
		t.Fatalf("response = %v", r)
	}
	if _, _, d, _ := f.counts(); d != 0 {
		t.Fatalf("DenyResponse was called %d times", d)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; rec.Ended != "denied" || rec.Degraded || rec.Verdict.Rule != fakeRuleID {
		t.Fatalf("record: %+v", rec)
	}
}
