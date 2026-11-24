// Package extproc is the gateway's Envoy external processor.
//
// Envoy runs it with request and response bodies in FULL_DUPLEX_STREAMED mode.
// In that mode the processor owns the body: every chunk Envoy sends must be
// answered with a StreamedBodyResponse carrying the bytes to forward.
//
// For each transaction it identifies the pod from the kernel connection table,
// streams the request body to the evaluator (pkg/plugin) and enforces the
// verdict, parses the response stream and times each chunk, and emits one
// Record. Every call into the evaluator is bounded (evalcall.go): a stalled or
// panicking evaluator fails the request, and the framework answers on its own
// when the evaluator cannot. With no evaluator every request passes.
//
// Two fault knobs exist for the hostile tests and are off by default:
// StallAfterChunks (stalled processor) and EarlyEOSAfterEvents (early EOS with
// synthetic terminal events).
package extproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	"github.com/kubescape/sandbox-gateway/internal/stale"
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

// Defaults and framework rule ids.
const (
	// DefaultChunkBudget is how long one response chunk, one write of the
	// request body to the evaluator, or one evaluator call may take.
	DefaultChunkBudget = 3 * time.Second
	// DefaultMaxEvaluatorCalls caps the evaluator calls in flight (decision 10).
	DefaultMaxEvaluatorCalls = 64
	// callbackBudget bounds DenyResponse and StreamError (decision 12).
	callbackBudget = 200 * time.Millisecond

	// RuleEvaluatorTimeout is the rule on a request the evaluator could not
	// decide: a call stalled, panicked or found no free slot after evaluation
	// began.
	RuleEvaluatorTimeout = "framework.evaluator-timeout"
	// RuleEvaluatorSaturated is the rule on a request that could not begin
	// evaluation because every slot was taken. It is decided by the pod's
	// fail posture.
	RuleEvaluatorSaturated = "framework.evaluator-saturated"
)

// Faults are test-only behaviours for the hostile tests.
type Faults struct {
	StallAfterChunks    int // stop answering after this many response body chunks; 0 = off
	EarlyEOSAfterEvents int // end the response after this many SSE events with synthetic terminal events; 0 = off
}

// Config configures the processor.
type Config struct {
	// Evaluator decides requests. nil means this build has none: nothing is
	// classified or evaluated and every request passes.
	Evaluator plugin.Evaluator
	// MaxEvaluatorCalls caps the evaluator calls in flight, stuck ones
	// included. 0 means DefaultMaxEvaluatorCalls.
	MaxEvaluatorCalls int
	Faults            Faults
	// ChunkBudget is the watchdog: if answering one response chunk takes
	// longer than this, a separate goroutine ends the response with the
	// evaluator's StreamError frame (fail closed), or with end of stream and
	// no frame. 0 disables the watchdog. It also bounds each write of the
	// request body to the evaluator and each evaluator call; there 0 means
	// DefaultChunkBudget.
	ChunkBudget time.Duration
	// Conns is the kernel's record of who opened each connection, keyed on the
	// pod socket's address and port, which Envoy reports as the source.address
	// request attribute. It is the only identity source. A request whose
	// connection is not in it is rejected; with no table every request is.
	Conns conntable.Table
	// Lookup names the workload that owns a cgroup. nil leaves the record with
	// the kernel half of the identity only.
	Lookup LookupFunc
	// Policies is the policy source (contract C11): the http sections of the
	// objects a workload's lookup names. nil turns the policy stage off: no
	// sections, nothing degraded, no decrypt-list guard. Only tests leave it
	// nil; the processor always sets it.
	Policies PolicySource
	// Stale decides when a workload's policy is too old to trust. nil means a
	// tracker with DefaultStaleAfter.
	Stale *stale.Tracker
	Emit  func(Record) // called once per transaction; default logs JSON
	Log   *slog.Logger
}

// DefaultStaleAfter is how long a workload's policy may go without a source
// before its decisions are degraded.
const DefaultStaleAfter = 5 * time.Minute

// PolicySource is what the server needs from the policy informers.
type PolicySource interface {
	// Resolve returns the cached http section of each reference, and counts
	// the references cached at another generation and those not cached.
	Resolve(refs []plugin.PolicyRef) (sections []plugin.PolicySection, outdated, missing int)
	// LostSince is the start of the oldest outage not yet over; zero when
	// connected.
	LostSince() time.Time
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
	TransactionID string    `json:"transaction_id"` // Envoy x-request-id; joined to the tap's id in stage 4
	Identity      *Identity `json:"identity,omitempty"`
	Downstream    string    `json:"downstream,omitempty"`   // source.address from Envoy
	PPv2Ignored   string    `json:"ppv2_ignored,omitempty"` // an identity the client claimed over PROXY protocol; never used
	RejectReason  string    `json:"reject_reason,omitempty"`
	TestOracle    string    `json:"test_oracle,omitempty"` // x-sandbox-test-oracle, set by the stage 1 test client
	Authority     string    `json:"authority,omitempty"`
	Method        string    `json:"method,omitempty"`
	Path          string    `json:"path,omitempty"`
	Protocol      string    `json:"protocol,omitempty"` // request.protocol from Envoy
	// RequestPosition is the request's ordinal on its HTTP/1.x connection,
	// from 1; 0 on HTTP/2, where it is not known.
	RequestPosition int `json:"request_position,omitempty"`
	// Provider and Model are what the evaluator's Classify returned.
	Provider string   `json:"provider,omitempty"`
	Model    string   `json:"model,omitempty"`
	Verdict  *Verdict `json:"verdict,omitempty"`
	// WouldDeny is a deny verdict in audit mode: the request passed.
	WouldDeny bool `json:"would_deny,omitempty"`
	// Degraded marks a request decided without a full evaluation.
	Degraded bool `json:"degraded,omitempty"`
	// EvaluatorError says which evaluator call failed and how.
	EvaluatorError    string `json:"evaluator_error,omitempty"`
	RequestBytes      int    `json:"request_bytes"`
	Status            string `json:"status,omitempty"`
	ContentEncoding   string `json:"content_encoding,omitempty"` // non-empty = compressed body the processor can't read
	ResponseChunks    int    `json:"response_chunks"`
	ResponseBytes     int    `json:"response_bytes"`
	SSEEvents         int    `json:"sse_events"`
	EventStreamFrames int    `json:"eventstream_frames,omitempty"` // Bedrock application/vnd.amazon.eventstream frames
	// StopReason is how the provider said the response ended, in its own
	// terms: the Anthropic stop_reason, the OpenAI chat finish_reason, or the
	// OpenAI Responses status ("completed", "incomplete", "failed").
	StopReason        string   `json:"stop_reason,omitempty"`
	FirstChunkAfterMs float64  `json:"first_chunk_after_ms,omitempty"` // request EOS to first response chunk, as seen here
	ChunkProcMaxUs    int64    `json:"chunk_proc_max_us"`
	ChunkProcAvgUs    int64    `json:"chunk_proc_avg_us"`
	EarlyEOS          bool     `json:"early_eos,omitempty"`
	WatchdogFired     bool     `json:"watchdog_fired,omitempty"`
	WebSocket         *WSStats `json:"websocket,omitempty"`
	ObservabilityMode bool     `json:"observability_mode,omitempty"`
	Ended             string   `json:"ended"` // eos | trailers | stream_closed | stream_error | watchdog | denied | rejected
}

// Verdict is the evaluator's verdict as the record carries it.
type Verdict struct {
	Action         string `json:"action"` // allow | deny
	Mode           string `json:"mode"`   // audit | enforce
	Rule           string `json:"rule,omitempty"`
	Origin         string `json:"origin,omitempty"`
	PolicyUID      string `json:"policy_uid,omitempty"`
	PolicyRevision int64  `json:"policy_revision,omitempty"`
}

func recordVerdict(v plugin.Verdict) *Verdict {
	return &Verdict{Action: v.Action, Mode: v.Mode, Rule: v.Rule, Origin: v.Origin,
		PolicyUID: v.PolicyUID, PolicyRevision: v.PolicyRevision}
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
	cfg     Config
	calls   *calls
	feeders atomic.Int64 // goroutines writing a request chunk to the evaluator
	// degraded counts the transactions decided with a degraded decision.
	degraded atomic.Int64
	pos      *positions
	Active   atomic.Int64
	Total    atomic.Int64
}

// DegradedDecisions is the number of transactions so far whose decision was
// degraded.
func (s *Server) DegradedDecisions() int64 { return s.degraded.Load() }

// StuckEvaluatorCalls is the number of evaluator calls still running past
// their deadline.
func (s *Server) StuckEvaluatorCalls() int64 { return s.calls.stuck.Load() }

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
	if cfg.Stale == nil {
		cfg.Stale = stale.New(DefaultStaleAfter, time.Now)
	}
	return &Server{cfg: cfg, calls: newCalls(cfg.MaxEvaluatorCalls), pos: newPositions(time.Now)}
}

// budget bounds one evaluator call or one write of the body to it.
func (s *Server) budget() time.Duration {
	if s.cfg.ChunkBudget > 0 {
		return s.cfg.ChunkBudget
	}
	return DefaultChunkBudget
}

// txn is the per-stream state. One ext_proc stream is one HTTP transaction.
type txn struct {
	rec                Record
	ctx                context.Context // ends when the transaction does
	policies           []plugin.PolicyRef
	lookupFailingSince time.Time
	sections           []plugin.PolicySection
	in                 input // the decision table's input, set by the policy stage
	headers            http.Header
	eval               *evaluation // nil when the request is not being evaluated
	held               []byte      // the newest request chunk, not forwarded until the verdict
	holding            bool
	wsIn               wsframe.Decoder
	wsOut              wsframe.Decoder
	reqEOSAt           time.Time
	parser             sse.Parser
	es                 *eventstream.Decoder // set when the response is a Bedrock event stream
	procTotal          time.Duration
	track              streamfmt.Tracker // items and stop reason of the response stream
	eosSent            bool
	emitted            bool

	// Shared with the watchdog goroutine.
	provider      atomic.Value // string: the provider Classify named
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
			frame := s.streamError(t, "watchdog")
			t.sendMu.Lock()
			if !t.closed { // Process may have returned while this goroutine waited
				_ = stream.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: streamed(frame, true)}})
				t.closed = true
			}
			t.sendMu.Unlock()
			return
		}
	}
}

// streamError is the frame that ends a stalled stream: the evaluator's
// StreamError for the request's provider. With no evaluator, or one that
// cannot answer within callbackBudget, it is nil and the stream just ends.
func (s *Server) streamError(t *txn, reason string) []byte {
	if s.cfg.Evaluator == nil {
		return nil
	}
	provider, _ := t.provider.Load().(string)
	frame, err := run(s.calls, context.Background(), callbackBudget, func(context.Context) []byte {
		return s.cfg.Evaluator.StreamError(provider, reason)
	})
	if err != nil {
		s.cfg.Log.Warn("StreamError gave no frame; ending the stream without one", "error", err)
		return nil
	}
	return frame
}

// Process handles one HTTP transaction.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	s.Active.Add(1)
	s.Total.Add(1)
	defer s.Active.Add(-1)
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	t := &txn{ctx: ctx}
	// Whatever way the transaction ends, an evaluation still running is
	// stopped: its pipe is closed, which unblocks Classify and any writer.
	defer func() {
		if t.eval != nil {
			t.eval.abort()
		}
	}()
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
		if t.rec.Degraded {
			s.degraded.Add(1)
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
		s.cfg.Stale.Forget(conn.CgroupID) // the workload is gone
		return "not_bound"
	}
	// The connection carries the binding it was made under. If the cgroup's
	// binding is another one now, the two tables do not describe the same pod,
	// and the posture read here would not be this connection's.
	if conn.BindingID != binding.BindingID {
		s.cfg.Log.Warn("connection and cgroup name different bindings",
			"conn_binding", conn.BindingID, "cgroup_binding", binding.BindingID, "cgroup", conn.CgroupID)
		return "binding_mismatch"
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
			s.cfg.Stale.Forget(conn.CgroupID) // the workload is gone
			return "not_bound"
		case err != nil:
			id.LookupError = err.Error()
		case w.BindingID != conn.BindingID:
			// The kernel tables decide the binding; the lookup only names
			// the workload. An answer about another binding (node-agent's
			// view or its cache lags a rebinding) does not describe this
			// connection, so none of it goes on the record.
			s.cfg.Log.Warn("lookup names another binding than the kernel tables",
				"lookup_binding", w.BindingID, "kernel_binding", conn.BindingID, "cgroup", conn.CgroupID)
			id.LookupError = fmt.Sprintf("binding_mismatch: the lookup names binding %d, the kernel tables %d", w.BindingID, conn.BindingID)
		default:
			id.Namespace, id.Pod, id.Container = w.Namespace, w.Pod, w.Container
			id.ControllerKind, id.ControllerName = w.Controller.Kind, w.Controller.Name
			for _, p := range w.Policies {
				t.policies = append(t.policies, plugin.PolicyRef{UID: p.UID, Generation: p.Generation})
			}
		}
		if !failingSince.IsZero() {
			t.lookupFailingSince = failingSince
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
			f := a.GetFields()
			t.rec.Downstream = f["source.address"].GetStringValue()
			t.rec.Protocol = f["request.protocol"].GetStringValue()
			id, hasID := f["connection.id"]
			t.rec.RequestPosition = s.pos.next(uint64(id.GetNumberValue()), hasID, t.rec.Downstream, t.rec.Protocol)
		}
		if reason := s.identify(stream.Context(), t); reason != "" {
			t.rec.Ended, t.rec.RejectReason = "rejected", reason
			return reject(reason), nil
		}
		t.headers = httpHeaders(v.RequestHeaders.GetHeaders())
		if v.RequestHeaders.GetEndOfStream() {
			t.reqEOSAt = time.Now()
		}
		// The identity goes into the audit metadata so the access log shows who
		// sent the request.
		resp := &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extprocv3.HeadersResponse{}},
			DynamicMetadata: auditMetadata(identityFields(t.rec.Identity))}
		pre := s.policyStage(t)
		switch {
		case pre.Block:
			// Known before any body: a host no policy decrypts (decision 5),
			// or a deny pod with nothing cached. Refused at the headers, so
			// none of the request reaches the provider. The provider is not
			// known yet, so the answer is the framework's own 403.
			t.rec.Verdict = &Verdict{Action: plugin.ActionDeny, Mode: plugin.ModeEnforce, Rule: pre.Rule}
			t.rec.Ended = "denied"
			return immediate(frameworkDeny(), s.auditMeta(t)), nil
		case !pre.CallEvaluate:
			resp.DynamicMetadata = s.auditMeta(t)
			return resp, nil
		}
		if s.cfg.Evaluator == nil {
			return resp, nil
		}
		// A request with no body, and a WebSocket upgrade, are decided here.
		// The client sets the upgrade header, so it must not be a way around
		// the evaluator: Classify gets an empty body and frames are never fed.
		noBody := v.RequestHeaders.GetEndOfStream() || t.rec.WebSocket != nil
		if blocked := s.startEvaluation(t, noBody); blocked != nil {
			return blocked, nil
		}
		if noBody && t.eval != nil {
			blocked, meta := s.decide(t)
			if blocked != nil {
				return blocked, nil
			}
			resp.DynamicMetadata = meta
		} else if t.eval == nil {
			resp.DynamicMetadata = s.auditMeta(t) // passed unevaluated: no slot, allow pod
		}
		return resp, nil

	case *extprocv3.ProcessingRequest_RequestBody:
		chunk := v.RequestBody.GetBody()
		eos := v.RequestBody.GetEndOfStream()
		t.rec.RequestBytes += len(chunk)
		if t.rec.WebSocket != nil {
			t.wsChunk(&t.wsIn, chunk, true)
			return bodyResponse(chunk, eos), nil
		}
		if eos {
			t.reqEOSAt = time.Now()
		}
		if t.eval == nil || t.eval.decided {
			return bodyResponse(chunk, eos), nil
		}
		if err := s.feed(t, chunk); err != nil {
			return s.evaluationFailed(t, "classify", err), nil
		}
		if !eos {
			// Forward one chunk behind. The newest chunk stays here until the
			// verdict, so a blocked request never reaches the upstream whole,
			// even when the client ends it with an empty chunk or with
			// trailers.
			prev, had := t.held, t.holding
			t.held, t.holding = chunk, true
			if !had {
				return nil, nil
			}
			return bodyResponse(prev, false), nil
		}
		if t.holding {
			chunk = append(t.held, chunk...)
			t.held, t.holding = nil, false
		}
		blocked, meta := s.decide(t)
		if blocked != nil {
			return blocked, nil
		}
		resp := bodyResponse(chunk, true)
		resp.DynamicMetadata = meta
		return resp, nil

	case *extprocv3.ProcessingRequest_RequestTrailers:
		resp := &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extprocv3.TrailersResponse{}}}
		// A request that ends in trailers never has a body chunk marked end of
		// stream, so this is where it is decided.
		if t.eval != nil && !t.eval.decided {
			t.reqEOSAt = time.Now()
			blocked, meta := s.decide(t)
			if blocked != nil {
				return blocked, nil
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
		// A body that ends in trailers has no chunk marked end of stream, so
		// the SSE parser is closed here: an event ended by a lone CR
		// completes only at the end.
		if t.rec.WebSocket == nil && t.es == nil && !t.eosSent {
			for _, ev := range t.parser.Close() {
				t.rec.SSEEvents++
				t.trackEvent(ev)
			}
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
	evs := t.parser.Feed(chunk)
	if *eos { // an event ended by a lone CR completes only at the end
		for _, ev := range t.parser.Close() {
			ev.End = len(chunk) // it ends at the last byte of this chunk
			evs = append(evs, ev)
		}
	}
	for _, ev := range evs {
		t.rec.SSEEvents++
		t.trackEvent(ev)
		if n := s.cfg.Faults.EarlyEOSAfterEvents; n > 0 && t.rec.SSEEvents >= n && !t.eosSent {
			// Hostile test 3: cut here at an event boundary and close the
			// turn with synthetic terminal events.
			// Forward exactly up to the end of the triggering event; later
			// events in the same chunk are dropped.
			term, stop := t.terminalEvents()
			*forward = append(append([]byte(nil), chunk[:ev.End]...), term...)
			t.eosSent = true
			t.rec.EarlyEOS = true
			t.rec.StopReason = stop
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

// trackEvent follows the items and the stop reason of the response stream, in
// whichever of the known formats it arrives.
func (t *txn) trackEvent(ev sse.Event) {
	t.track.Event(ev)
	if t.track.StopReason != "" {
		t.rec.StopReason = t.track.StopReason
	}
}

// anthropicOpen returns the open Anthropic content blocks, or none when the
// stream is in another format.
func (t *txn) anthropicOpen() []int {
	if t.track.Format != streamfmt.Anthropic {
		return nil
	}
	return t.track.Open()
}

// terminalEvents ends the stream the way the provider would, in the stream's
// format, so SDKs finish the turn instead of raising. It returns the events
// and the stop reason they give. A stream whose format is not known yet is
// ended as an Anthropic one.
func (t *txn) terminalEvents() ([]byte, string) {
	var b strings.Builder
	switch t.track.Format {
	case streamfmt.OpenAIChat:
		b.WriteString("data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
		b.WriteString("data: [DONE]\n\n")
		return []byte(b.String()), "stop"
	case streamfmt.OpenAIResponses:
		b.WriteString("event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n")
		return []byte(b.String()), "incomplete"
	}
	// The tracker also holds open items of other formats; only Anthropic
	// content blocks are closed with content_block_stop.
	for _, idx := range t.anthropicOpen() {
		fmt.Fprintf(&b, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", idx)
	}
	b.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":0}}\n\n")
	b.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return []byte(b.String()), "end_turn"
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

// httpHeaders converts the request headers for the evaluator. Pseudo-headers
// (":method", ":path", ...) are left out; they reach it as fields of Request.
func httpHeaders(hm *corev3.HeaderMap) http.Header {
	out := http.Header{}
	for _, h := range hm.GetHeaders() {
		if strings.HasPrefix(h.GetKey(), ":") {
			continue
		}
		v := h.GetValue()
		if len(h.GetRawValue()) > 0 {
			v = string(h.GetRawValue())
		}
		out.Add(h.GetKey(), v)
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
