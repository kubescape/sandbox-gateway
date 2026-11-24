package extproc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// errAborted closes the body pipe when the transaction ends before the body
// does, or when a write to it ran over its budget.
var errAborted = errors.New("extproc: evaluation aborted")

// classified is what Classify returned.
type classified struct {
	provider, model string
	hasModel        bool
}

// evaluation is the evaluator's work on one request: Classify reading the
// body from a pipe while the request streams, then Evaluate.
type evaluation struct {
	pr       *io.PipeReader
	pw       *io.PipeWriter
	classify *call[classified]
	decided  bool
}

// abort closes both ends of the body pipe. A writer and a Classify blocked on
// it return at once.
func (e *evaluation) abort() {
	_ = e.pw.CloseWithError(errAborted)
	_ = e.pr.CloseWithError(errAborted)
}

// startEvaluation starts Classify on the request body. With noBody, Classify
// gets an empty body and the caller decides right away. It returns a response
// only when the request is blocked here: no slot was free for Classify and the
// pod's fail posture is deny (decision 12). With no slot on an allow pod the
// request passes unevaluated and t.eval stays nil.
func (s *Server) startEvaluation(t *txn, noBody bool) *extprocv3.ProcessingResponse {
	pr, pw := io.Pipe()
	if noBody {
		_ = pw.Close()
	}
	ev, host, path := s.cfg.Evaluator, t.rec.Authority, t.rec.Path
	cl, err := begin(s.calls, t.ctx, func(context.Context) classified {
		// Classify may stop reading before the end; closing the read end then
		// lets later writes return at once.
		defer func() { _ = pr.Close() }()
		provider, model, has := ev.Classify(host, path, pr)
		return classified{provider, model, has}
	})
	if err != nil {
		_ = pr.Close()
		return s.saturated(t)
	}
	t.eval = &evaluation{pr: pr, pw: pw, classify: cl}
	return nil
}

// saturated decides a request that could not begin evaluation by the pod's
// fail posture: a deny pod gets the framework 403, an allow pod passes.
// Either way the decision is degraded.
func (s *Server) saturated(t *txn) *extprocv3.ProcessingResponse {
	t.rec.Degraded = true
	t.rec.EvaluatorError = "classify: " + errNoSlot.Error()
	s.cfg.Log.Warn("no free evaluator slot; deciding by the fail posture",
		"txn", t.rec.TransactionID, "stuck", s.calls.stuck.Load())
	if t.rec.Identity != nil && t.rec.Identity.Posture == conntable.PostureDeny {
		t.rec.Verdict = &Verdict{Action: plugin.ActionDeny, Mode: plugin.ModeEnforce, Rule: RuleEvaluatorSaturated}
		t.rec.Ended = "denied"
		return immediate(frameworkDeny(), s.auditMeta(t))
	}
	return nil
}

// feed writes one request chunk to Classify. The write runs in its own
// goroutine and the server waits for it at most the budget; past that, the
// pipe is closed and the request fails.
func (s *Server) feed(t *txn, chunk []byte) error {
	if len(chunk) == 0 {
		return nil
	}
	errc := make(chan error, 1)
	pw := t.eval.pw
	s.feeders.Add(1)
	go func() {
		defer s.feeders.Add(-1)
		_, err := pw.Write(chunk)
		errc <- err
	}()
	timer := time.NewTimer(s.budget())
	defer timer.Stop()
	select {
	case err := <-errc:
		// ErrClosedPipe: Classify returned before the end of the body and
		// needs no more of it.
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			return err
		}
		return nil
	case <-timer.C:
		t.eval.abort() // unblocks the writer
		// The request fails without waiting for Classify. If it is still
		// running it holds its slot, so it counts as stuck until it returns.
		t.eval.classify.abandon()
		err := <-errc
		s.cfg.Log.Debug("body write to the evaluator aborted", "txn", t.rec.TransactionID, "error", err)
		return errTimeout
	}
}

// decide ends the body, waits for Classify, calls Evaluate and applies the
// verdict. It returns the immediate response that blocks the request, or the
// audit metadata for a request that passes.
func (s *Server) decide(t *txn) (blocked *extprocv3.ProcessingResponse, meta *structpb.Struct) {
	t.eval.decided = true
	_ = t.eval.pw.Close()
	cls, err := t.eval.classify.wait(s.budget())
	t.eval.abort()
	if err != nil {
		return s.evaluationFailed(t, "classify", err), nil
	}
	t.rec.Provider, t.rec.Model = cls.provider, cls.model
	t.provider.Store(cls.provider)
	req := plugin.Request{
		Workload: t.workload(), Sections: t.sections, Degraded: t.rec.Degraded,
		Host: t.rec.Authority, Method: t.rec.Method, Path: t.rec.Path,
		Headers: t.headers, Model: cls.model, HasModel: cls.hasModel,
	}
	ev := s.cfg.Evaluator
	v, err := run(s.calls, t.ctx, s.budget(), func(ctx context.Context) plugin.Verdict {
		return ev.Evaluate(ctx, req)
	})
	if err != nil {
		return s.evaluationFailed(t, "evaluate", err), nil
	}
	t.rec.Verdict = recordVerdict(v)
	in := t.in
	in.HasEvaluator, in.Verdict = true, v
	o := decide(in)
	t.rec.Degraded = t.rec.Degraded || o.Degraded
	if o.Block {
		return s.block(t, v), nil
	}
	// An audit deny, and an enforce deny the table let through because the
	// decision is degraded on an allow pod.
	t.rec.WouldDeny = v.Action == plugin.ActionDeny
	return nil, s.auditMeta(t)
}

// policyStage resolves the workload's policies, asks the staleness tracker,
// and runs the decision table before any body is read. With no policy source
// it says to evaluate, and nothing else.
func (s *Server) policyStage(t *txn) outcome {
	t.in = input{HasEvaluator: s.cfg.Evaluator != nil, Sections: 1, HostInDecryptList: true}
	if t.rec.Identity != nil {
		t.in.Posture = t.rec.Identity.Posture
	}
	if s.cfg.Policies == nil {
		return outcome{CallEvaluate: true}
	}
	sections, outdated, missing := s.cfg.Policies.Resolve(t.policies)
	var cgroup uint64
	if t.rec.Identity != nil {
		cgroup = t.rec.Identity.CgroupID
	}
	unresolved := outdated + missing
	t.sections = sections
	t.in.Sections, t.in.Unresolved = len(sections), unresolved
	t.in.Stale = s.cfg.Stale.Observe(cgroup, t.lookupFailingSince, s.cfg.Policies.LostSince(), unresolved > 0)
	t.in.HostInDecryptList = inDecryptList(sections, t.rec.Authority)
	o := decide(t.in)
	t.rec.Degraded = o.Degraded
	return o
}

// evaluationFailed refuses a request whose evaluation began and could not
// finish (decision 6): the evaluator's DenyResponse, rule
// RuleEvaluatorTimeout.
func (s *Server) evaluationFailed(t *txn, which string, err error) *extprocv3.ProcessingResponse {
	if t.eval != nil {
		t.eval.decided = true
		t.eval.abort()
	}
	t.rec.EvaluatorError = which + ": " + err.Error()
	s.cfg.Log.Warn("evaluator call failed; refusing the request", "txn", t.rec.TransactionID, "call", which, "error", err)
	return s.block(t, plugin.Verdict{Action: plugin.ActionDeny, Mode: plugin.ModeEnforce,
		Rule: RuleEvaluatorTimeout, Provider: t.rec.Provider, Model: t.rec.Model})
}

// block refuses the request with the evaluator's DenyResponse. A verdict, once
// given, stands: when DenyResponse finds no slot, stalls or panics, the
// framework's own 403 goes out instead, and the evaluator is not called again
// (decision 12).
func (s *Server) block(t *txn, v plugin.Verdict) *extprocv3.ProcessingResponse {
	t.rec.Verdict = recordVerdict(v)
	t.rec.Ended = "denied"
	t.held, t.holding = nil, false
	type answer struct {
		status  int
		headers http.Header
		body    []byte
	}
	ev, provider := s.cfg.Evaluator, t.rec.Provider
	a, err := run(s.calls, t.ctx, callbackBudget, func(context.Context) answer {
		st, h, b := ev.DenyResponse(provider, v)
		return answer{st, h, b}
	})
	if err != nil {
		if t.rec.EvaluatorError != "" {
			t.rec.EvaluatorError += "; "
		}
		t.rec.EvaluatorError += "deny_response: " + err.Error()
		return immediate(frameworkDeny(), s.auditMeta(t))
	}
	ir := &extprocv3.ImmediateResponse{
		Status:  &typev3.HttpStatus{Code: typev3.StatusCode(a.status)}, //nolint:gosec // an HTTP status
		Headers: headerMutation(a.headers),
		Body:    a.body,
		Details: "sandbox_gateway_deny",
	}
	return immediate(ir, s.auditMeta(t))
}

// frameworkDeny is the 403 the framework sends when the evaluator cannot
// answer (decision 12).
func frameworkDeny() *extprocv3.ImmediateResponse {
	return &extprocv3.ImmediateResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
		Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
			{Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}}}},
		Body:    []byte(`{"error":{"type":"gateway_error","message":"request blocked by the gateway"}}`),
		Details: "sandbox_gateway_framework_deny",
	}
}

func immediate(ir *extprocv3.ImmediateResponse, meta *structpb.Struct) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response:        &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: ir},
		DynamicMetadata: meta,
	}
}

func headerMutation(h http.Header) *extprocv3.HeaderMutation {
	m := &extprocv3.HeaderMutation{}
	for k, vs := range h {
		for _, v := range vs {
			m.SetHeaders = append(m.SetHeaders, &corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: strings.ToLower(k), RawValue: []byte(v)},
				AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
			})
		}
	}
	return m
}

// workload is the request's pod, as the evaluator sees it.
func (t *txn) workload() plugin.Workload {
	w := plugin.Workload{Policies: t.policies}
	if id := t.rec.Identity; id != nil {
		w.Namespace, w.Pod, w.Container = id.Namespace, id.Pod, id.Container
		w.ControllerKind, w.ControllerName = id.ControllerKind, id.ControllerName
		w.BindingID, w.Posture = id.BindingID, id.Posture
	}
	return w
}

// auditMeta is the dynamic metadata for the access log: the identity and the
// verdict.
func (s *Server) auditMeta(t *txn) *structpb.Struct {
	fields := identityFields(t.rec.Identity)
	fields["provider"], fields["model"] = t.rec.Provider, t.rec.Model
	fields["would_deny"], fields["degraded"] = t.rec.WouldDeny, t.rec.Degraded
	if v := t.rec.Verdict; v != nil {
		fields["rule_id"], fields["action"], fields["mode"] = v.Rule, v.Action, v.Mode
	}
	if t.rec.EvaluatorError != "" {
		fields["evaluator_error"] = t.rec.EvaluatorError
	}
	return auditMetadata(fields)
}
