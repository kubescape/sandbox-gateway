// Package extproc is the PoC's Envoy external processor: the policy core.
//
// Envoy runs it with request and response bodies in FULL_DUPLEX_STREAMED mode.
// In that mode the processor owns the body: every chunk Envoy sends must be
// answered with a StreamedBodyResponse carrying the bytes to forward. The PoC
// forwards every byte unchanged (audit only) while it:
//
//   - buffers the request body (up to a cap), evaluates the one intent at end
//     of stream and writes the decision into dynamic metadata ("kubescape.sandbox.audit")
//     for the access log;
//   - parses the SSE response as it streams and times each chunk;
//   - emits one Record per transaction (stage 4 turns these into OTLP).
//
// Two fault knobs exist for the hostile tests and are off by default:
// StallAfterChunks (stalled processor, AC6) and EarlyEOSAfterEvents (early
// EOS with synthetic terminal events, AC7).
package extproc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kubescape/sandbox-gateway/internal/eventstream"
	"github.com/kubescape/sandbox-gateway/internal/sse"
	"github.com/kubescape/sandbox-gateway/internal/wsframe"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// Namespaces of dynamic metadata. Envoy's ext_proc filter must list
// AttributionNS in forwarding_namespaces and AuditNS in receiving_namespaces.
const (
	AttributionNS = "kubescape.sandbox.attribution" // written by the proxy_protocol listener filter from PPv2 TLVs
	AuditNS       = "kubescape.sandbox.audit"
)

// Faults are test-only behaviours for the hostile tests.
type Faults struct {
	StallAfterChunks    int // stop answering after this many response body chunks; 0 = off
	EarlyEOSAfterEvents int // end the response after this many SSE events with synthetic terminal events; 0 = off
}

// Config configures the processor.
type Config struct {
	// Evaluator decides inspected requests. nil means this build has no rule
	// evaluator: nothing is scanned, no decision is recorded and nothing is blocked.
	Evaluator plugin.Evaluator
	// Enforce turns would_deny into a block: the final request chunk is not
	// forwarded (the upstream only ever saw an incomplete body, then a reset) and
	// the client gets a provider-shaped 403. A degraded decision never blocks.
	Enforce bool
	Faults  Faults
	// ChunkBudget is the AC6 watchdog: if answering one response chunk takes
	// longer than this, a separate goroutine ends the response with an
	// Anthropic error event (fail closed). 0 disables it. It covers a slow or
	// hung policy step while the gRPC stream still works; a wedged process
	// needs Envoy's idle timeout or a restart (see README).
	ChunkBudget time.Duration
	// AttrLookup is the stage 1 5-tuple path: given Envoy's downstream address
	// ("ip:port", from the source.address request attribute) it returns the
	// attribution the redirector recorded. Used when no PPv2 identity arrived.
	AttrLookup func(addr string) (map[string]string, error)
	Emit       func(Record) // called once per transaction; default logs JSON
	Log        *slog.Logger
}

// Record is the per-transaction audit record.
type Record struct {
	TransactionID     string            `json:"transaction_id"` // Envoy x-request-id; joined to the tap's id in stage 4
	Attribution       map[string]string `json:"attribution,omitempty"`
	Downstream        string            `json:"downstream,omitempty"`  // source.address from Envoy
	TestOracle        string            `json:"test_oracle,omitempty"` // x-sandbox-test-oracle, set by the stage 1 test client
	Authority         string            `json:"authority,omitempty"`
	Method            string            `json:"method,omitempty"`
	Path              string            `json:"path,omitempty"`
	Decision          *plugin.Decision  `json:"decision,omitempty"`
	RequestBytes      int               `json:"request_bytes"`
	Status            string            `json:"status,omitempty"`
	ContentEncoding   string            `json:"content_encoding,omitempty"` // non-empty = compressed body the processor can't read
	ResponseChunks    int               `json:"response_chunks"`
	ResponseBytes     int               `json:"response_bytes"`
	SSEEvents         int               `json:"sse_events"`
	EventStreamFrames int               `json:"eventstream_frames,omitempty"` // Bedrock application/vnd.amazon.eventstream frames
	StopReason        string            `json:"stop_reason,omitempty"`
	FirstChunkAfterMs float64           `json:"first_chunk_after_ms,omitempty"` // request EOS to first response chunk, as seen here
	ChunkProcMaxUs    int64             `json:"chunk_proc_max_us"`
	ChunkProcAvgUs    int64             `json:"chunk_proc_avg_us"`
	EarlyEOS          bool              `json:"early_eos,omitempty"`
	WatchdogFired     bool              `json:"watchdog_fired,omitempty"`
	WebSocket         *WSStats          `json:"websocket,omitempty"`
	ObservabilityMode bool              `json:"observability_mode,omitempty"`
	Ended             string            `json:"ended"` // eos | trailers | stream_closed | stream_error | watchdog
}

// WSStats summarises an upgraded WebSocket connection (S5): messages decoded
// per direction, and JSON-RPC methods seen in text messages (MCP over WebSocket).
type WSStats struct {
	MessagesIn  int      `json:"messages_in"`
	MessagesOut int      `json:"messages_out"`
	BytesIn     int      `json:"payload_bytes_in"`
	BytesOut    int      `json:"payload_bytes_out"`
	Methods     []string `json:"jsonrpc_methods,omitempty"`
	Errors      int      `json:"decode_errors,omitempty"`
}

// Server implements ExternalProcessorServer.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	cfg    Config
	Active atomic.Int64
	Total  atomic.Int64
}

// New returns a processor.
func New(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Emit == nil {
		log := cfg.Log
		cfg.Emit = func(r Record) {
			b, _ := json.Marshal(r)
			log.Info("transaction", "record", json.RawMessage(b))
		}
	}
	return &Server{cfg: cfg}
}

// txn is the per-stream state. One ext_proc stream is one HTTP transaction.
type txn struct {
	rec        Record
	scan       plugin.Scan // request body, scanned as it streams (no buffering); nil when not inspected
	wsIn       wsframe.Decoder
	wsOut      wsframe.Decoder
	reqEOSAt   time.Time
	parser     sse.Parser
	es         *eventstream.Decoder // set when the response is a Bedrock event stream
	procTotal  time.Duration
	openBlocks map[int]bool
	eosSent    bool
	emitted    bool

	// Shared with the watchdog goroutine.
	inflightSince atomic.Int64 // unix nanos a response chunk started; 0 when none
	fired         atomic.Bool
	sendMu        sync.Mutex
	closed        bool // the watchdog ended the response; guarded by sendMu
}

// send forwards resp unless the watchdog already ended the response.
func (t *txn) send(stream extprocv3.ExternalProcessor_ProcessServer, resp *extprocv3.ProcessingResponse) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if t.closed {
		return nil
	}
	return stream.Send(resp)
}

// watch ends the response with an error event if one chunk takes longer than budget.
func (s *Server) watch(stream extprocv3.ExternalProcessor_ProcessServer, t *txn, budget time.Duration, done <-chan struct{}) {
	tick := budget / 10
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	tk := time.NewTicker(tick)
	defer tk.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-tk.C:
			since := t.inflightSince.Load()
			if since == 0 || now.UnixNano()-since < budget.Nanoseconds() || t.fired.Swap(true) {
				continue
			}
			s.cfg.Log.Warn("watchdog: chunk over budget, ending response fail-closed", "budget", budget)
			t.sendMu.Lock()
			_ = stream.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
				ResponseBody: streamed(watchdogErrorEvent, true)}})
			t.closed = true
			t.sendMu.Unlock()
			return
		}
	}
}

// watchdogErrorEvent is how the Anthropic API itself ends a stream that fails
// mid-flight, so SDKs raise a normal API error instead of a protocol error.
var watchdogErrorEvent = []byte("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"egress gateway: policy processing timed out, response ended (fail closed)\"}}\n\n")

// Process handles one HTTP transaction.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	s.Active.Add(1)
	s.Total.Add(1)
	defer s.Active.Add(-1)
	t := &txn{openBlocks: map[int]bool{}}
	if b := s.cfg.ChunkBudget; b > 0 {
		done := make(chan struct{})
		defer close(done)
		go s.watch(stream, t, b, done)
	}
	emit := func(how string) {
		if t.emitted {
			return
		}
		t.emitted = true
		if t.fired.Load() {
			how = "watchdog"
			t.rec.WatchdogFired = true
		}
		t.rec.Ended = how
		if n := t.rec.ResponseChunks; n > 0 {
			t.rec.ChunkProcAvgUs = t.procTotal.Microseconds() / int64(n)
		}
		s.cfg.Emit(t.rec)
	}

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			emit("stream_closed")
			return nil
		}
		if err != nil {
			emit("stream_error")
			return err
		}
		if req.GetObservabilityMode() {
			t.rec.ObservabilityMode = true
		}
		_, isRespBody := req.Request.(*extprocv3.ProcessingRequest_ResponseBody)
		if isRespBody {
			t.inflightSince.Store(time.Now().UnixNano())
		}
		resp, err := s.handle(stream, t, req)
		t.inflightSince.Store(0)
		if err != nil {
			emit("stream_error")
			return err
		}
		if resp == nil {
			continue
		}
		if err := t.send(stream, resp); err != nil {
			emit("stream_error")
			return err
		}
		if t.rec.Ended != "" {
			emit(t.rec.Ended)
		}
	}
}

// inspects reports whether the evaluator looks at this request, and starts its
// scan on first use.
func (s *Server) inspects(t *txn) bool {
	if s.cfg.Evaluator == nil || !s.cfg.Evaluator.Inspects(t.rec.Path) {
		return false
	}
	if t.scan == nil {
		t.scan = s.cfg.Evaluator.NewScan()
	}
	return true
}

func (s *Server) handle(stream extprocv3.ExternalProcessor_ProcessServer, t *txn, req *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, error) {
	switch v := req.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		h := headerMap(v.RequestHeaders.GetHeaders())
		t.rec.TransactionID = h["x-request-id"]
		t.rec.Authority = h[":authority"]
		t.rec.Method = h[":method"]
		t.rec.Path = h[":path"]
		t.rec.Attribution = attribution(req.GetMetadataContext())
		t.rec.TestOracle = h["x-sandbox-test-oracle"]
		// With the 5-tuple table in use, the kernel-observed identity wins. A PPv2
		// header on the same connection is self-declared by the client, so it is
		// ignored and flagged (gap 2: a pod could claim another pod's identity).
		var claimed map[string]string
		if s.cfg.AttrLookup != nil && t.rec.Attribution != nil {
			claimed, t.rec.Attribution = t.rec.Attribution, nil
		}
		if strings.EqualFold(h["upgrade"], "websocket") {
			t.rec.WebSocket = &WSStats{}
		}
		if a := req.GetAttributes()["envoy.filters.http.ext_proc"]; a != nil {
			t.rec.Downstream = a.GetFields()["source.address"].GetStringValue()
		}
		if t.rec.Attribution == nil && s.cfg.AttrLookup != nil && t.rec.Downstream != "" {
			if attr, err := s.cfg.AttrLookup(t.rec.Downstream); err == nil {
				t.rec.Attribution = attr
			} else {
				t.rec.Attribution = map[string]string{"source": "5tuple-miss", "error": err.Error()}
			}
		}
		if claimed != nil {
			if t.rec.Attribution == nil {
				t.rec.Attribution = map[string]string{}
			}
			t.rec.Attribution["ppv2_ignored"] = "pod_uid=" + claimed["pod_uid"] + " pid=" + claimed["pid"]
		}
		if v.RequestHeaders.GetEndOfStream() {
			t.reqEOSAt = time.Now()
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{}}}, nil

	case *extprocv3.ProcessingRequest_RequestBody:
		chunk := v.RequestBody.GetBody()
		eos := v.RequestBody.GetEndOfStream()
		t.rec.RequestBytes += len(chunk)
		if t.rec.WebSocket != nil {
			t.wsChunk(&t.wsIn, chunk, true)
		} else if s.inspects(t) {
			t.scan.Feed(chunk)
		}
		resp := &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: streamed(chunk, eos)}}
		if eos {
			t.reqEOSAt = time.Now()
			if s.inspects(t) {
				d := t.scan.Decide()
				t.rec.Decision = &d
				fields := map[string]any{
					"rule_id": d.RuleID, "action": string(d.Action), "model": d.Model, "reason": d.Reason,
					"class_version": d.ClassVersion, "degraded": d.Degraded,
				}
				// The access log can't read the connection-level PPv2 metadata,
				// so the identity rides along in the request's kubescape.sandbox.audit.
				for k, v := range t.rec.Attribution {
					fields[k] = v
				}
				if s.cfg.Enforce && d.Action == plugin.WouldDeny && !d.Degraded {
					d.Action = plugin.Deny
					t.rec.Decision = &d
					fields["action"] = string(d.Action)
					t.rec.Ended = "denied"
					return &extprocv3.ProcessingResponse{
						Response:        &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: denyResponse(d.Reason)},
						DynamicMetadata: auditMetadata(fields),
					}, nil
				}
				resp.DynamicMetadata = auditMetadata(fields)
			}
		}
		return resp, nil

	case *extprocv3.ProcessingRequest_RequestTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extprocv3.TrailersResponse{}}}, nil

	case *extprocv3.ProcessingRequest_ResponseHeaders:
		h := headerMap(v.ResponseHeaders.GetHeaders())
		t.rec.Status = h[":status"]
		// Envoy asks upstream for identity; a provider that compresses anyway leaves the
		// processor blind to the body, so record it.
		if ce := h["content-encoding"]; ce != "" && ce != "identity" {
			t.rec.ContentEncoding = ce
		}
		if strings.HasPrefix(h["content-type"], "application/vnd.amazon.eventstream") {
			t.es = &eventstream.Decoder{}
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{}}}, nil

	case *extprocv3.ProcessingRequest_ResponseBody:
		return s.responseChunk(stream, t, v.ResponseBody.GetBody(), v.ResponseBody.GetEndOfStream())

	case *extprocv3.ProcessingRequest_ResponseTrailers:
		if t.rec.Ended == "" {
			t.rec.Ended = "trailers"
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extprocv3.TrailersResponse{}}}, nil
	}
	return nil, fmt.Errorf("unexpected processing request %T", req.Request)
}

func (s *Server) responseChunk(stream extprocv3.ExternalProcessor_ProcessServer, t *txn, chunk []byte, eos bool) (*extprocv3.ProcessingResponse, error) {
	start := time.Now()
	t.rec.ResponseChunks++
	t.rec.ResponseBytes += len(chunk)
	if t.rec.ResponseChunks == 1 && !t.reqEOSAt.IsZero() {
		t.rec.FirstChunkAfterMs = float64(start.Sub(t.reqEOSAt).Microseconds()) / 1000
	}

	// Hostile test 2: stop answering. Envoy has no message timeout in
	// FULL_DUPLEX_STREAMED, so this shows what the client sees.
	if n := s.cfg.Faults.StallAfterChunks; n > 0 && t.rec.ResponseChunks > n {
		s.cfg.Log.Warn("fault: stalling processor", "txn", t.rec.TransactionID, "chunk", t.rec.ResponseChunks)
		<-stream.Context().Done()
		return nil, stream.Context().Err()
	}

	// After an early EOS Envoy has ended the response; answer with empty
	// bodies so the stream drains. What Envoy does with the upstream here is
	// one of the things S3 measures.
	if t.eosSent {
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: streamed(nil, false)}}, nil
	}

	forward := chunk
	if t.rec.WebSocket != nil {
		t.wsChunk(&t.wsOut, chunk, false)
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: streamed(chunk, eos)}}, nil
	}
	if t.es != nil {
		if err := t.eventStreamChunk(chunk); err != nil {
			s.cfg.Log.Warn("eventstream decode", "txn", t.rec.TransactionID, "error", err)
			t.es = nil // stop decoding; the bytes still pass through untouched
		}
	} else {
		t.sseChunk(s, chunk, &forward, &eos)
	}

	elapsed := time.Since(start)
	t.procTotal += elapsed
	if us := elapsed.Microseconds(); us > t.rec.ChunkProcMaxUs {
		t.rec.ChunkProcMaxUs = us
	}
	resp := &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
		ResponseBody: streamed(forward, eos)}}
	if eos {
		resp.DynamicMetadata = auditMetadata(map[string]any{
			"sse_events": float64(t.rec.SSEEvents), "stop_reason": t.rec.StopReason, "early_eos": t.rec.EarlyEOS,
		})
		if t.rec.Ended == "" {
			t.rec.Ended = "eos"
		}
	}
	return resp, nil
}

// sseChunk parses an SSE response chunk, tracks the Anthropic events, and
// applies the early-EOS fault (hostile test 3).
func (t *txn) sseChunk(s *Server, chunk []byte, forward *[]byte, eos *bool) {
	for _, ev := range t.parser.Feed(chunk) {
		t.rec.SSEEvents++
		t.track(ev)
		if n := s.cfg.Faults.EarlyEOSAfterEvents; n > 0 && t.rec.SSEEvents >= n && !t.eosSent {
			// Hostile test 3: cut here at an event boundary and close the
			// turn with synthetic terminal events.
			// Forward exactly up to the end of the triggering event; later
			// events in the same chunk are dropped.
			*forward = append(append([]byte(nil), chunk[:ev.End]...), t.terminalEvents()...)
			t.eosSent = true
			t.rec.EarlyEOS = true
			t.rec.StopReason = "end_turn"
			*eos = true
			break
		}
	}
}

// eventStreamChunk decodes Bedrock event-stream frames. Each "chunk" frame
// carries one Anthropic stream event as base64 JSON in {"bytes": ...}; those
// are tracked like SSE events. Bytes are forwarded unchanged (audit).
func (t *txn) eventStreamChunk(chunk []byte) error {
	frames, _, err := t.es.Feed(chunk)
	for _, f := range frames {
		t.rec.EventStreamFrames++
		if f.Get(":event-type") != "chunk" {
			continue
		}
		var p struct {
			Bytes []byte `json:"bytes"`
		}
		if json.Unmarshal(f.Payload, &p) == nil && len(p.Bytes) > 0 {
			t.rec.SSEEvents++
			t.track(sse.Event{Data: string(p.Bytes)})
		}
	}
	return err
}

// wsChunk decodes WebSocket frames in one direction and updates the stats.
func (t *txn) wsChunk(d *wsframe.Decoder, chunk []byte, in bool) {
	msgs, err := d.Feed(chunk)
	ws := t.rec.WebSocket
	if err != nil {
		ws.Errors++
	}
	for _, m := range msgs {
		if m.Opcode != wsframe.OpText && m.Opcode != wsframe.OpBinary {
			continue
		}
		if in {
			ws.MessagesIn++
			ws.BytesIn += m.Len
		} else {
			ws.MessagesOut++
			ws.BytesOut += m.Len
		}
		var rpc struct {
			Method string `json:"method"`
		}
		if m.Opcode == wsframe.OpText && json.Unmarshal(m.Payload, &rpc) == nil && rpc.Method != "" && len(ws.Methods) < 16 {
			ws.Methods = append(ws.Methods, rpc.Method)
		}
	}
}

// denyResponse is a 403 shaped like the Anthropic API's own permission_error, so
// SDKs raise their normal PermissionDenied error and don't retry.
func denyResponse(reason string) *extprocv3.ImmediateResponse {
	body, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{
		"type": "permission_error", "message": "blocked by egress policy: " + reason}})
	return &extprocv3.ImmediateResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
		Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
			{Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}}}},
		Body:    body,
		Details: "egress_policy_deny",
	}
}

// track follows content blocks and stop_reason in Anthropic stream events.
func (t *txn) track(ev sse.Event) {
	var m struct {
		Type  string `json:"type"`
		Index *int   `json:"index"`
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
	}
	if json.Unmarshal([]byte(ev.Data), &m) != nil {
		return
	}
	switch m.Type {
	case "content_block_start":
		if m.Index != nil {
			t.openBlocks[*m.Index] = true
		}
	case "content_block_stop":
		if m.Index != nil {
			delete(t.openBlocks, *m.Index)
		}
	case "message_delta":
		if m.Delta.StopReason != "" {
			t.rec.StopReason = m.Delta.StopReason
		}
	}
}

// terminalEvents closes open content blocks and ends the message the way the
// Anthropic API does, so SDKs finish the turn instead of raising.
func (t *txn) terminalEvents() []byte {
	var b strings.Builder
	for idx := range t.openBlocks {
		fmt.Fprintf(&b, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", idx)
	}
	b.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":0}}\n\n")
	b.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return []byte(b.String())
}

func streamed(body []byte, eos bool) *extprocv3.BodyResponse {
	return &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{
		BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_StreamedResponse{
			StreamedResponse: &extprocv3.StreamedBodyResponse{Body: body, EndOfStream: eos}}}}}
}

func auditMetadata(fields map[string]any) *structpb.Struct {
	inner, err := structpb.NewStruct(fields)
	if err != nil {
		return nil
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{AuditNS: structpb.NewStructValue(inner)}}
}

func headerMap(hm *corev3.HeaderMap) map[string]string {
	out := map[string]string{}
	for _, h := range hm.GetHeaders() {
		v := h.GetValue()
		if len(h.GetRawValue()) > 0 {
			v = string(h.GetRawValue())
		}
		out[strings.ToLower(h.GetKey())] = v
	}
	return out
}

func attribution(md *corev3.Metadata) map[string]string {
	ns, ok := md.GetFilterMetadata()[AttributionNS]
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, v := range ns.GetFields() {
		switch x := v.Kind.(type) {
		case *structpb.Value_StringValue:
			out[k] = x.StringValue
		case *structpb.Value_NumberValue:
			out[k] = fmt.Sprint(x.NumberValue)
		default:
			out[k] = v.String()
		}
	}
	return out
}
