package extproc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/record"
)

// exactlyOne waits for the first record, then checks no second one follows.
func exactlyOne(t *testing.T, h *harness) Record {
	t.Helper()
	r := h.waitRecords(t, 1)[0]
	time.Sleep(200 * time.Millisecond)
	if n := len(h.waitRecords(t, 1)); n != 1 {
		t.Fatalf("%d records for one transaction", n)
	}
	return r
}

func TestOneRecordPerTransaction(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		_, h := start(t, Config{Evaluator: allowAll()})
		if _, blocked := oneRequest(t, h, "api.anthropic.com"); blocked {
			t.Fatal("blocked")
		}
		c := exactlyOne(t, h).C7()
		if c.Verdict != "allow" || c.DestinationState != record.DestinationInspected {
			t.Fatalf("record: %+v", c)
		}
	})
	t.Run("blocked", func(t *testing.T) {
		_, h := start(t, Config{Evaluator: enforceDeny()})
		if _, blocked := oneRequest(t, h, "api.anthropic.com"); !blocked {
			t.Fatal("not blocked")
		}
		c := exactlyOne(t, h).C7()
		if c.Verdict != "deny" || c.Mode != "enforce" || c.Rule != fakeRuleID || c.DestinationState != record.DestinationBlocked {
			t.Fatalf("record: %+v", c)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		_, h := start(t, Config{Evaluator: allowAll()})
		st := h.stream(t)
		if r := headersFrom(t, st, "10.9.9.9:1234"); !is403(r) {
			t.Fatalf("answer: %v", r)
		}
		must(t, st.CloseSend())
		c := exactlyOne(t, h).C7()
		if c.Verdict != "deny" || c.Rule != "framework.no-connection-entry" || c.DestinationState != record.DestinationBlocked {
			t.Fatalf("record: %+v", c)
		}
	})
	t.Run("watchdog", func(t *testing.T) {
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
		recv(t, st)
		recv(t, st) // the watchdog's stream error
		cancel()
		r := exactlyOne(t, h)
		if a := r.C7().Attrs(); a["gateway.watchdog_fired"] != true || a["gateway.ended"] != "watchdog" {
			t.Fatalf("attrs: %v", a)
		}
	})
}

func TestDegradedMarkedOnRecord(t *testing.T) {
	h := staleServer(t, enforceDeny(), "allow")
	oneRequest(t, h, "api.anthropic.com")
	if a := h.waitRecords(t, 1)[0].C7().Attrs(); a["degraded"] != true || a["would_deny"] != true {
		t.Fatalf("attrs: %v", a)
	}
}

func TestFailOpenWindowFromGate(t *testing.T) {
	for gate, want := range map[uint8]bool{
		conntable.GateRedirecting: false, conntable.GateFailingOpen: true, conntable.GateRecovering: true,
	} {
		tb := newTable()
		b := tb.bindings[testCgroup]
		b.Gate = gate
		tb.bindings[testCgroup] = b
		_, h := start(t, Config{Evaluator: allowAll(), Conns: tb})
		oneRequest(t, h, "api.anthropic.com")
		if got := h.waitRecords(t, 1)[0].C7().Attrs()["fail_open_window"]; got != want {
			t.Errorf("gate %d: fail_open_window = %v", gate, got)
		}
	}
}

// No request or response bytes reach the record: not the OTLP attributes,
// not the JSON log line.
func TestNoBodyBytesInRecord(t *testing.T) {
	const marker = "MARKER-7f3e9a"
	_, h := start(t, Config{Evaluator: allowAll()})
	st := h.stream(t)
	sendHeaders(t, st)
	sendBody(t, st, strings.Replace(reqBody, `"hi"`, `"`+marker+`"`, 1), true)
	recv(t, st)
	must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: hdrs(":status", "200", "content-type", "text/event-stream")}}}))
	recv(t, st)
	resp := strings.Replace(respSSE[2], `"lo"`, `"`+marker+`"`, 1)
	for i, c := range []string{respSSE[0], respSSE[1], resp, respSSE[3]} {
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(c), EndOfStream: i == 3}}}))
		recv(t, st)
	}
	must(t, st.CloseSend())
	r := h.waitRecords(t, 1)[0]
	if r.SSEEvents == 0 {
		t.Fatal("the response was not parsed, so the test proves nothing")
	}
	for k, v := range r.C7().Attrs() {
		if strings.Contains(fmt.Sprint(v), marker) {
			t.Errorf("attribute %s carries body bytes: %v", k, v)
		}
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), marker) {
		t.Errorf("the log record carries body bytes: %s", b)
	}
}

// requestOn sends one request's headers on a connection and returns its
// record's position attribute.
func requestOn(t *testing.T, h *harness, connID float64, protocol string) any {
	t.Helper()
	before := 0
	h.mu.Lock()
	before = len(h.records)
	h.mu.Unlock()
	s, _ := structpb.NewStruct(map[string]any{"source.address": testSource, "connection.id": connID, "request.protocol": protocol})
	st := h.stream(t)
	must(t, st.Send(&extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": s},
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: hdrs(":method", "GET", ":path", "/v1/models", ":authority", "api.anthropic.com"), EndOfStream: true}}}))
	recv(t, st)
	must(t, st.CloseSend())
	return h.waitRecords(t, before+1)[before].C7().Attrs()["request_position"]
}

func TestRequestPositionOnHTTP1(t *testing.T) {
	_, h := start(t, Config{})
	for want := 1; want <= 3; want++ {
		if got := requestOn(t, h, 7, "HTTP/1.1"); got != want {
			t.Fatalf("request %d on connection 7: position %v", want, got)
		}
	}
	if got := requestOn(t, h, 8, "HTTP/1.1"); got != 1 {
		t.Fatalf("first request on connection 8: position %v", got)
	}
	if got := requestOn(t, h, 9, "HTTP/2"); got != nil {
		t.Fatalf("HTTP/2 request has a position: %v", got)
	}
}

func TestPositionsNeverGuessAfterOverflow(t *testing.T) {
	p := newPositions(time.Now)
	for id := uint64(1); id <= maxPositions; id++ {
		p.next(id, true, testSource, "HTTP/1.1")
	}
	if n := p.next(maxPositions+1, true, testSource, "HTTP/1.1"); n != 0 {
		t.Fatalf("a connection the full map turned away got position %d", n)
	}
	delete(p.conns, connKey{1, testSource}) // room again
	if n := p.next(maxPositions+1, true, testSource, "HTTP/1.1"); n != 0 {
		t.Fatalf("the turned-away connection got position %d later", n)
	}
	if n := p.next(maxPositions+2, true, testSource, "HTTP/1.1"); n != 1 {
		t.Fatalf("a newer connection got position %d", n)
	}
	if n := p.next(5, false, testSource, "HTTP/1.1"); n != 0 {
		t.Fatalf("no connection id: position %d", n)
	}
}
