// Package app wires the processor together and runs it: the ext_proc gRPC
// server, the record outputs and the debug server. The parts that differ
// between builds, the connection table, the workload lookup and the
// evaluator, come in through Config, so a test program can run the same
// server against stubs.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/extproc"
	"github.com/kubescape/sandbox-gateway/internal/otlpemit"
	"github.com/kubescape/sandbox-gateway/internal/runutil"
	"github.com/kubescape/sandbox-gateway/internal/stale"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// Config is everything Run needs.
type Config struct {
	Listen string // unix:///path or host:port
	Conns  conntable.Table
	Lookup extproc.LookupFunc
	// Evaluator decides requests; nil passes every request and reports the
	// evaluator as unavailable.
	Evaluator         plugin.Evaluator
	MaxEvaluatorCalls int
	// Policies is the policy source; Run starts it. nil turns the policy
	// stage off and the health path answers 200 from the start (tests only).
	Policies   PolicySource
	StaleAfter time.Duration
	// HealthSocket serves GET /healthz/processor (decision 3); empty turns it off.
	HealthSocket string
	ChunkBudget  time.Duration
	Faults       extproc.Faults
	RecordsFile  string // also append records here as JSON lines
	OTLPEndpoint string
	DebugAddr    string
	Log          *slog.Logger
}

// PolicySource is the policy informers as Run needs them.
type PolicySource interface {
	extproc.PolicySource
	Synced() bool
	Run(ctx context.Context)
}

// DefaultHealthSocket is where the processor serves its health path.
const DefaultHealthSocket = "unix:///run/kubescape-sandbox/processor-health.sock"

// Flags registers the flags every processor build shares and returns the
// Config they fill. The caller sets Conns, Lookup and Evaluator.
func Flags(fs *flag.FlagSet) *Config {
	c := &Config{}
	fs.StringVar(&c.Listen, "listen", "unix:///run/kubescape-sandbox/extproc.sock", "gRPC listen address: unix:///path or host:port")
	fs.IntVar(&c.Faults.StallAfterChunks, "fault-stall-after-chunks", 0, "TEST ONLY: stop answering after N response chunks")
	fs.IntVar(&c.Faults.EarlyEOSAfterEvents, "fault-early-eos-after-events", 0, "TEST ONLY: end the response after N SSE events with synthetic terminal events")
	fs.DurationVar(&c.ChunkBudget, "chunk-budget", extproc.DefaultChunkBudget, "watchdog and evaluator budget: end the response fail-closed if one chunk takes longer than this, and fail a request whose evaluator call does; 0 disables the watchdog")
	fs.IntVar(&c.MaxEvaluatorCalls, "max-evaluator-calls", extproc.DefaultMaxEvaluatorCalls, "evaluator calls in flight, stuck ones included; past it a request is decided by the pod's fail posture")
	fs.DurationVar(&c.StaleAfter, "stale-after", extproc.DefaultStaleAfter, "a workload's policy this long without a source makes its decisions degraded")
	fs.StringVar(&c.HealthSocket, "health-socket", DefaultHealthSocket, "where to serve GET /healthz/processor: unix:///path or host:port; empty disables")
	fs.StringVar(&c.OTLPEndpoint, "otlp-endpoint", "", "OTLP/HTTP endpoint for transaction records (e.g. http://otel-collector:4318)")
	fs.StringVar(&c.RecordsFile, "records", "", "also append transaction records as JSON lines to this file")
	fs.StringVar(&c.DebugAddr, "debug-addr", "127.0.0.1:9102", "debug HTTP address; it has no authentication, so keep it on loopback; empty disables")
	return c
}

// Run serves until ctx ends, then stops the gRPC server gracefully.
func Run(ctx context.Context, c Config) error {
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Conns == nil {
		return errors.New("app: no connection table")
	}
	log := c.Log

	var mu sync.Mutex
	var out *json.Encoder
	if c.RecordsFile != "" {
		f, err := os.OpenFile(c.RecordsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("app: open records: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = json.NewEncoder(f)
	}
	var otlp *otlpemit.Exporter
	if c.OTLPEndpoint != "" {
		otlp = otlpemit.New(c.OTLPEndpoint, os.Getenv("NODE_NAME"), os.Getenv("ACCOUNT_ID"))
		stop := make(chan struct{})
		defer close(stop)
		go otlp.Run(time.Second, stop, func(err error) { log.Warn("otlp export", "error", err) })
		log.Info("otlp export enabled", "endpoint", c.OTLPEndpoint)
	}
	if c.StaleAfter <= 0 {
		c.StaleAfter = extproc.DefaultStaleAfter
	}
	tracker := stale.New(c.StaleAfter, time.Now)
	if c.Conns != nil {
		go tracker.Run(ctx, time.Minute, func(cgroupID uint64) (bool, error) {
			_, ok, err := c.Conns.Binding(cgroupID)
			return ok, err
		})
	}
	var policies extproc.PolicySource
	if c.Policies != nil {
		policies = c.Policies
		go c.Policies.Run(ctx)
	}
	srv := extproc.New(extproc.Config{
		Policies:          policies,
		Stale:             tracker,
		Evaluator:         c.Evaluator,
		MaxEvaluatorCalls: c.MaxEvaluatorCalls,
		Conns:             c.Conns,
		Lookup:            c.Lookup,
		Faults:            c.Faults,
		ChunkBudget:       c.ChunkBudget,
		Log:               log,
		Emit: func(r extproc.Record) {
			log.Info("transaction", "record", r)
			if otlp != nil {
				otlp.Add(time.Now(), RecordAttrs(r))
			}
			if out != nil {
				mu.Lock()
				_ = out.Encode(r)
				mu.Unlock()
			}
		},
	})
	runutil.ServeDebug(c.DebugAddr, func() any { return stats(srv, c.Evaluator) })
	if c.HealthSocket != "" {
		hl, err := runutil.Listen(c.HealthSocket)
		if err != nil {
			return fmt.Errorf("app: health socket: %w", err)
		}
		hs := &http.Server{Handler: health(srv, c.Evaluator, c.Policies), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = hs.Serve(hl) }()
		go func() { <-ctx.Done(); _ = hs.Close() }()
	}
	if c.Faults.StallAfterChunks > 0 || c.Faults.EarlyEOSAfterEvents > 0 {
		log.Warn("fault injection enabled", "stall_after_chunks", c.Faults.StallAfterChunks, "early_eos_after_events", c.Faults.EarlyEOSAfterEvents)
	}

	lis, err := runutil.Listen(c.Listen)
	if err != nil {
		return fmt.Errorf("app: listen: %w", err)
	}
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	go func() {
		<-ctx.Done()
		g.GracefulStop()
	}()
	log.Info("processor listening", "addr", c.Listen, "evaluator", EvaluatorState(c.Evaluator))
	return g.Serve(lis)
}

// EvaluatorState is "available" when the build has an evaluator and
// "unavailable" when it has none.
func EvaluatorState(e plugin.Evaluator) string {
	if e == nil {
		return "unavailable"
	}
	return "available"
}

// health serves GET /healthz/processor (decision 3): 503 until the policy
// informers have synced once, then 200 with the evaluator state and the
// counters the node controller reads.
func health(srv *extproc.Server, e plugin.Evaluator, p PolicySource) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz/processor", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		if p != nil && !p.Synced() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"reason": "policy informers have not synced"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"evaluator":           EvaluatorState(e),
			"degradedDecisions":   srv.DegradedDecisions(),
			"stuckEvaluatorCalls": srv.StuckEvaluatorCalls(),
		})
	})
	return mux
}

// stats is what the debug server's /stats answers.
func stats(srv *extproc.Server, e plugin.Evaluator) map[string]any {
	return map[string]any{
		"active": srv.Active.Load(), "total": srv.Total.Load(),
		"evaluator": EvaluatorState(e), "stuckEvaluatorCalls": srv.StuckEvaluatorCalls(),
		"degradedDecisions": srv.DegradedDecisions(),
	}
}

// RecordAttrs maps a transaction record onto OTLP attributes. Keys follow the
// sandbox event schema and OTel semantic conventions where one exists.
func RecordAttrs(r extproc.Record) map[string]any {
	a := map[string]any{
		"http.capture.transaction_id":   r.TransactionID,
		"http.request.method":           r.Method,
		"server.address":                r.Authority,
		"url.path":                      r.Path,
		"http.response.status_code":     r.Status,
		"gateway.request_bytes":         r.RequestBytes,
		"gateway.response_bytes":        r.ResponseBytes,
		"gateway.sse_events":            r.SSEEvents,
		"gateway.ended":                 r.Ended,
		"gateway.reject_reason":         r.RejectReason,
		"gateway.ppv2_ignored":          r.PPv2Ignored,
		"gateway.first_chunk_after_ms":  r.FirstChunkAfterMs,
		"gateway.watchdog_fired":        r.WatchdogFired,
		"gateway.early_eos":             r.EarlyEOS,
		"gen_ai.response.finish_reason": r.StopReason,
	}
	if id := r.Identity; id != nil {
		a["namespace"], a["pod"], a["container"] = id.Namespace, id.Pod, id.Container
		a["controller_kind"], a["controller_name"] = id.ControllerKind, id.ControllerName
		a["fail_posture"] = id.Posture
		a["conn_local_addr"], a["conn_local_port"] = id.ConnLocalAddr, int(id.ConnLocalPort)
		a["orig_dst"] = id.OrigDst
		a["gateway.binding_id"] = int(id.BindingID)
		a["gateway.cgroup_id"] = int64(id.CgroupID) //nolint:gosec // an id, carried as is
		a["gateway.pid"] = int(id.PID)
		a["gateway.lookup_failing_since"] = id.LookupFailingSince
		a["gateway.lookup_error"] = id.LookupError
	}
	a["gen_ai.system"] = r.Provider
	a["gen_ai.request.model"] = r.Model
	a["policy.would_deny"] = r.WouldDeny
	a["policy.degraded"] = r.Degraded
	a["gateway.evaluator_error"] = r.EvaluatorError
	if v := r.Verdict; v != nil {
		a["policy.rule_id"] = v.Rule
		a["policy.action"] = v.Action
		a["policy.mode"] = v.Mode
		a["policy.uid"] = v.PolicyUID
		a["policy.revision"] = v.PolicyRevision
		a["policy.origin"] = v.Origin
	}
	return a
}
