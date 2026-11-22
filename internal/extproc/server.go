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
	"context"
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

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/eventstream"
	"github.com/kubescape/sandbox-gateway/internal/lookup"
	"github.com/kubescape/sandbox-gateway/internal/sse"
	"github.com/kubescape/sandbox-gateway/internal/streamfmt"
	"github.com/kubescape/sandbox-gateway/internal/wsframe"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// Namespaces of dynamic metadata. Envoy's ext_proc filter must list
// AttributionNS in forwarding_namespaces and AuditNS in receiving_namespaces.
const (
	// AttributionNS is where a proxy_protocol listener filter would put the
	// identity a client claims in PROXY protocol TLVs. The processor never uses
	// it; it only flags that one arrived.
	AttributionNS = "kubescape.sandbox.attribution"
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
	// Enforce turns would_deny into a block: the request body is forwarded one
	// chunk behind, so the last chunk with data is never sent (the upstream only
	// ever saw an incomplete body, then a reset) and the client gets a
	// provider-shaped 403. A degraded decision never blocks.
	Enforce bool
	Faults  Faults
	// ChunkBudget is the AC6 watchdog: if answering one response chunk takes
	// longer than this, a separate goroutine ends the response with an
	// Anthropic error event (fail closed). 0 disables it. It covers a slow or
	// hung policy step while the gRPC stream still works; a wedged process
	// needs Envoy's idle timeout or a restart (see README).
	ChunkBudget time.Duration
	// Conns is the kernel's record of who opened each connection, keyed on the
	// pod socket's address and port, which Envoy reports as the source.address
	// request attribute. It is the only identity source. A request whose
	// connection is not in it is rejected; with no table every request is.
	Conns conntable.Table
	// Lookup names the workload that owns a cgroup. nil leaves the record with
	// the kernel half of the identity only.
	Lookup LookupFunc
	Emit   func(Record) // called once per transaction; default logs JSON
	Log    *slog.Logger
}

// LookupFunc returns the workload that owns a cgroup. failingSince is zero
// while the lookup source answers; otherwise the workload comes from a cache
// and failingSince says since when. lookup.ErrNotBound means the pod is not
// bound. (*lookup.Client).Workload has this shape.
type LookupFunc func(ctx context.Context, cgroupID uint64) (w lookup.Workload, failingSince time.Time, err error)

// Identity is who sent a request: the connection's entry in the kernel table,
// the pod's binding, and the workload node-agent names for its cgroup.
type Identity struct {
	Namespace      string `json:"namespace,omitempty"`
	Pod            string `json:"pod,omitempty"`
	Container      string `json:"container,omitempty"`
	ControllerKind string `json:"controller_kind,omitempty"`
	ControllerName string `json:"controller_name,omitempty"`
	BindingID      uint32 `json:"binding_id"`
	Posture        string `json:"fail_posture"` // allow | deny, from the bindings table
	Gate           uint8  `json:"gate,omitempty"`
	CgroupID       uint64 `json:"cgroup_id"`
	PID            uint32 `json:"pid"`
	ConnLocalAddr  string `json:"conn_local_addr"` // the pod socket's address and port,
	ConnLocalPort  uint16 `json:"conn_local_port"` // as in the conns key
	OrigDst        string `json:"orig_dst"`        // where the pod was connecting to
	// LookupFailingSince is set when the workload came from the lookup cache
	// because node-agent's socket was not answering.
	LookupFailingSince string `json:"lookup_failing_since,omitempty"`
	// LookupError is set when the workload could not be named at all.
	LookupError string `json:"lookup_error,omitempty"`
}

// Record is the per-transaction audit record.
type Record struct {
	TransactionID     string           `json:"transaction_id"` // Envoy x-request-id; joined to the tap's id in stage 4
	Identity          *Identity        `json:"identity,omitempty"`
	Downstream        string           `json:"downstream,omitempty"`   // source.address from Envoy
	PPv2Ignored       string           `json:"ppv2_ignored,omitempty"` // an identity the client claimed over PROXY protocol; never used
	RejectReason      string           `json:"reject_reason,omitempty"`
	TestOracle        string           `json:"test_oracle,omitempty"` // x-sandbox-test-oracle, set by the stage 1 test client
	Authority         string           `json:"authority,omitempty"`
	Method            string           `json:"method,omitempty"`
	Path              string           `json:"path,omitempty"`
	Decision          *plugin.Decision `json:"decision,omitempty"`
	RequestBytes      int              `json:"request_bytes"`
	Status            string           `json:"status,omitempty"`
	ContentEncoding   string           `json:"content_encoding,omitempty"` // non-empty = compressed body the processor can't read
	ResponseChunks    int              `json:"response_chunks"`
	ResponseBytes     int              `json:"response_bytes"`
	SSEEvents         int              `json:"sse_events"`
	EventStreamFrames int              `json:"eventstream_frames,omitempty"` // Bedrock application/vnd.amazon.eventstream frames
	StopReason        string           `json:"stop_reason,omitempty"`
	FirstChunkAfterMs float64          `json:"first_chunk_after_ms,omitempty"` // request EOS to first response chunk, as seen here
	ChunkProcMaxUs    int64            `json:"chunk_proc_max_us"`
	ChunkProcAvgUs    int64            `json:"chunk_proc_avg_us"`
	EarlyEOS          bool             `json:"early_eos,omitempty"`
	WatchdogFired     bool             `json:"watchdog_fired,omitempty"`
	WebSocket         *WSStats         `json:"websocket,omitempty"`
	ObservabilityMode bool             `json:"observability_mode,omitempty"`
	Ended             string           `json:"ended"` // eos | trailers | stream_closed | stream_error | watchdog | denied | rejected
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
	rec       Record
	scan      plugin.Scan // request body, scanned as it streams (no buffering); nil when not inspected
	held      []byte      // enforce: the newest request chunk, not yet forwarded
	holding   bool
	wsIn      wsframe.Decoder
	wsOut     wsframe.Decoder
	reqEOSAt  time.Time
	parser    sse.Parser
	es        *eventstream.Decoder // set when the response is a Bedrock event stream
	procTotal time.Duration
	track     streamfmt.Tracker // items and stop reason of the response stream
	eosSent   bool
	emitted   bool

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
			if !t.closed { // Process may have returned while this goroutine waited
				_ = stream.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: streamed(watchdogErrorEvent, true)}})
				t.closed = true
			}
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
	t := &txn{}
	// gRPC forbids Send once the handler has returned. Taking sendMu here waits
	// for a watchdog Send in flight and stops any later one.
	defer func() {
		t.sendMu.Lock()
		t.closed = true
		t.sendMu.Unlock()
	}()
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

// RuleUnevaluatedUpgrade is the rule id on a request the framework refuses to
// pass unexamined: a WebSocket upgrade on a path the evaluator inspects. The
// body of such a request is frames, which the evaluator cannot read.
const RuleUnevaluatedUpgrade = "framework.websocket-on-inspected-path"

// verdict records a decision on the transaction and returns the audit metadata
// for the access log. denied is true when enforce mode blocks the request: a
// would_deny that is not degraded.
func (s *Server) verdict(t *txn, d plugin.Decision) (meta *structpb.Struct, denied bool) {
	if s.cfg.Enforce && d.Action == plugin.WouldDeny && !d.Degraded {
		d.Action = plugin.Deny
		denied = true
		t.rec.Ended = "denied"
	}
	t.rec.Decision = &d
	fields := map[string]any{
		"rule_id": d.RuleID, "action": string(d.Action), "model": d.Model, "reason": d.Reason,
		"class_version": d.ClassVersion, "degraded": d.Degraded,
	}
	for k, v := range identityFields(t.rec.Identity) {
		fields[k] = v
	}
	return auditMetadata(fields), denied
}

func deny(d *plugin.Decision, meta *structpb.Struct) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response:        &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: denyResponse(d.Reason)},
		DynamicMetadata: meta,
	}
}

// identify finds who sent the request, from the kernel table and node-agent's
// lookup, and puts it on the record. It returns a non-empty reason when the
// request must be rejected.
func (s *Server) identify(ctx context.Context, t *txn) (rejectReason string) {
	if s.cfg.Conns == nil {
		return "no_connection_table"
	}
	key, err := conntable.ParseKey(t.rec.Downstream)
	if err != nil {
		return "no_source_address"
	}
	// Read on every request and never cached here: the kernel reuses an
	// address and port for another pod's connection once the first one closes.
	conn, ok, err := s.cfg.Conns.Conn(key)
	if err != nil {
		s.cfg.Log.Error("connection table read failed", "error", err)
		return "connection_table_error"
	}
	if !ok {
		return "no_connection_entry"
	}
	binding, ok, err := s.cfg.Conns.Binding(conn.CgroupID)
	if err != nil {
		s.cfg.Log.Error("bindings table read failed", "error", err)
		return "connection_table_error"
	}
	if !ok {
		return "not_bound"
	}
	id := &Identity{
		BindingID: conn.BindingID, Posture: binding.Posture, Gate: binding.Gate,
		CgroupID: conn.CgroupID, PID: conn.PID,
		ConnLocalAddr: key.Addr.String(), ConnLocalPort: key.Port, OrigDst: conn.OrigDst.String(),
	}
	if s.cfg.Lookup != nil {
		w, failingSince, err := s.cfg.Lookup(ctx, conn.CgroupID)
		switch {
		case errors.Is(err, lookup.ErrNotBound):
			return "not_bound"
		case err != nil:
			id.LookupError = err.Error()
		default:
			id.Namespace, id.Pod, id.Container = w.Namespace, w.Pod, w.Container
			id.ControllerKind, id.ControllerName = w.Controller.Kind, w.Controller.Name
		}
		if !failingSince.IsZero() {
			id.LookupFailingSince = failingSince.UTC().Format(time.RFC3339)
		}
	}
	t.rec.Identity = id
	return ""
}

// reject refuses a request the processor cannot attribute to a bound pod.
func reject(reason string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
				{Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("text/plain")}}}},
			Body:    []byte("sandbox gateway: this connection is not attributed to a bound pod (" + reason + ")\n"),
			Details: reason,
		}}}
}

// identityFields is the part of the identity the access log shows.
func identityFields(id *Identity) map[string]any {
	if id == nil {
		return map[string]any{}
	}
	return map[string]any{
		"namespace": id.Namespace, "pod": id.Pod, "container": id.Container,
		"binding_id": float64(id.BindingID), "fail_posture": id.Posture,
		"orig_dst": id.OrigDst,
	}
}

func (s *Server) handle(stream extprocv3.ExternalProcessor_ProcessServer, t *txn, req *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, error) {
	switch v := req.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		h := headerMap(v.RequestHeaders.GetHeaders())
		t.rec.TransactionID = h["x-request-id"]
		t.rec.Authority = h[":authority"]
		t.rec.Method = h[":method"]
		t.rec.Path = h[":path"]
		t.rec.TestOracle = h["x-sandbox-test-oracle"]
		// A PROXY protocol identity on the connection is declared by the client,
		// so a pod could claim to be another pod with it. It is never used, only
		// flagged.
		if claimed := attribution(req.GetMetadataContext()); claimed != nil {
			t.rec.PPv2Ignored = "pod_uid=" + claimed["pod_uid"] + " pid=" + claimed["pid"]
		}
		if strings.EqualFold(h["upgrade"], "websocket") {
			t.rec.WebSocket = &WSStats{}
		}
		if a := req.GetAttributes()["envoy.filters.http.ext_proc"]; a != nil {
			t.rec.Downstream = a.GetFields()["source.address"].GetStringValue()
		}
		if reason := s.identify(stream.Context(), t); reason != "" {
			t.rec.Ended, t.rec.RejectReason = "rejected", reason
			return reject(reason), nil
		}
		if v.RequestHeaders.GetEndOfStream() {
			t.reqEOSAt = time.Now()
		}
		// The identity goes into the audit metadata so the access log shows who
		// sent the request.
		resp := &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extprocv3.HeadersResponse{}},
			DynamicMetadata: auditMetadata(identityFields(t.rec.Identity))}
		// The client sets the upgrade header, so it must not be a way around the
		// evaluator: the request is decided here, without its body.
		if t.rec.WebSocket != nil && s.cfg.Evaluator != nil && s.cfg.Evaluator.Inspects(t.rec.Path) {
			meta, denied := s.verdict(t, plugin.Decision{RuleID: RuleUnevaluatedUpgrade, Action: plugin.WouldDeny,
				Reason: "websocket upgrade on an inspected path cannot be evaluated"})
			if denied {
				return deny(t.rec.Decision, meta), nil
			}
			resp.DynamicMetadata = meta
		}
		return resp, nil

	case *extprocv3.ProcessingRequest_RequestBody:
		chunk := v.RequestBody.GetBody()
		eos := v.RequestBody.GetEndOfStream()
		t.rec.RequestBytes += len(chunk)
		inspected := t.rec.WebSocket == nil && s.inspects(t)
		if t.rec.WebSocket != nil {
			t.wsChunk(&t.wsIn, chunk, true)
		} else if inspected {
			t.scan.Feed(chunk)
		}
		if !eos {
			if !inspected || !s.cfg.Enforce {
				return bodyResponse(chunk, false), nil
			}
			// Enforce: forward one chunk behind. The newest chunk stays here until
			// the decision, so a denied request never reaches the upstream whole,
			// even when the client ends it with an empty chunk or with trailers.
			prev, had := t.held, t.holding
			t.held, t.holding = chunk, true
			if !had {
				return nil, nil
			}
			return bodyResponse(prev, false), nil
		}
		t.reqEOSAt = time.Now()
		if t.holding {
			chunk = append(t.held, chunk...)
			t.held, t.holding = nil, false
		}
		resp := bodyResponse(chunk, true)
		if inspected {
			meta, denied := s.verdict(t, t.scan.Decide())
			if denied {
				return deny(t.rec.Decision, meta), nil
			}
			resp.DynamicMetadata = meta
		}
		return resp, nil

	case *extprocv3.ProcessingRequest_RequestTrailers:
		resp := &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extprocv3.TrailersResponse{}}}
		// A request that ends in trailers never has a body chunk marked end of
		// stream, so this is where it is decided.
		if t.rec.WebSocket == nil && t.rec.Decision == nil && s.inspects(t) {
			t.reqEOSAt = time.Now()
			meta, denied := s.verdict(t, t.scan.Decide())
			if denied {
				return deny(t.rec.Decision, meta), nil
			}
			resp.DynamicMetadata = meta
			if t.holding {
				held := t.held
				t.held, t.holding = nil, false
				if err := t.send(stream, bodyResponse(held, false)); err != nil {
					return nil, err
				}
			}
		}
		return resp, nil

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
		t.trackEvent(ev)
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
			t.trackEvent(sse.Event{Data: string(p.Bytes)})
		}
	}
	return err
}

// wsChunk decodes WebSocket frames in one direction and updates the stats.
func (t *txn) wsChunk(d *wsframe.Decoder, chunk []byte, in bool) {
	if d.Dead() { // one protocol error ends decoding for this direction
		return
	}
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

// trackEvent follows the items and the stop reason of the response stream, in
// whichever of the known formats it arrives.
func (t *txn) trackEvent(ev sse.Event) {
	t.track.Event(ev)
	if t.track.StopReason != "" {
		t.rec.StopReason = t.track.StopReason
	}
}

// terminalEvents closes open content blocks and ends the message the way the
// Anthropic API does, so SDKs finish the turn instead of raising.
func (t *txn) terminalEvents() []byte {
	var b strings.Builder
	for _, idx := range t.track.Open() {
		fmt.Fprintf(&b, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", idx)
	}
	b.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":0}}\n\n")
	b.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return []byte(b.String())
}

func bodyResponse(body []byte, eos bool) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
		RequestBody: streamed(body, eos)}}
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
