// Command processor is an Envoy external processor (ext_proc) that parses AI
// provider traffic and records it without changing it. No rule evaluator is
// wired in here (see pkg/plugin), so it makes no decisions.
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"sync"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/kubescape/sandbox-gateway/internal/attrmap"
	"github.com/kubescape/sandbox-gateway/internal/extproc"
	"github.com/kubescape/sandbox-gateway/internal/otlpemit"
	"github.com/kubescape/sandbox-gateway/internal/runutil"
)

func main() {
	listen := flag.String("listen", "unix:///run/kubescape-sandbox/extproc.sock", "gRPC listen address: unix:///path or host:port")
	stall := flag.Int("fault-stall-after-chunks", 0, "TEST ONLY: stop answering after N response chunks")
	early := flag.Int("fault-early-eos-after-events", 0, "TEST ONLY: end the response after N SSE events with synthetic terminal events")
	budget := flag.Duration("chunk-budget", 0, "AC6 watchdog: end the response fail-closed if one chunk takes longer than this; 0 disables")
	attrPin := flag.String("attribution-map", "", "stage 1: pinned conns map (e.g. /sys/fs/bpf/kubescape-sandbox/http/conns) for 5-tuple attribution")
	otlpEndpoint := flag.String("otlp-endpoint", "", "stage 4: OTLP/HTTP endpoint for transaction records (e.g. http://otel-collector:4318)")
	enforce := flag.Bool("enforce", false, "block would_deny decisions with a provider-shaped 403; has no effect without a rule evaluator")
	records := flag.String("records", "", "also append transaction records as JSON lines to this file")
	debug := flag.String("debug-addr", ":9102", "debug HTTP address; empty disables")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	var mu sync.Mutex
	var out *json.Encoder
	if *records != "" {
		f, err := os.OpenFile(*records, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Error("open records", "error", err)
			os.Exit(1)
		}
		out = json.NewEncoder(f)
	}
	var lookup func(string) (map[string]string, error)
	if *attrPin != "" {
		m, err := attrmap.Open(*attrPin)
		if err != nil {
			log.Error("open attribution map", "error", err)
			os.Exit(1)
		}
		lookup = m.Lookup
		log.Info("5-tuple attribution enabled", "map", *attrPin)
	}
	var otlp *otlpemit.Exporter
	if *otlpEndpoint != "" {
		otlp = otlpemit.New(*otlpEndpoint, os.Getenv("NODE_NAME"), os.Getenv("ACCOUNT_ID"))
		go otlp.Run(time.Second, make(chan struct{}), func(err error) { log.Warn("otlp export", "error", err) })
		log.Info("otlp export enabled", "endpoint", *otlpEndpoint)
	}
	srv := extproc.New(extproc.Config{
		Enforce:     *enforce,
		AttrLookup:  lookup,
		Faults:      extproc.Faults{StallAfterChunks: *stall, EarlyEOSAfterEvents: *early},
		ChunkBudget: *budget,
		Log:         log,
		Emit: func(r extproc.Record) {
			log.Info("transaction", "record", r)
			if otlp != nil {
				otlp.Add(time.Now(), recordAttrs(r))
			}
			if out != nil {
				mu.Lock()
				_ = out.Encode(r)
				mu.Unlock()
			}
		},
	})
	runutil.ServeDebug(*debug, func() any {
		return map[string]int64{"active": srv.Active.Load(), "total": srv.Total.Load()}
	})
	if *stall > 0 || *early > 0 {
		log.Warn("fault injection enabled", "stall_after_chunks", *stall, "early_eos_after_events", *early)
	}

	lis, err := runutil.Listen(*listen)
	if err != nil {
		log.Error("listen", "error", err)
		os.Exit(1)
	}
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	log.Info("processor listening", "addr", *listen, "evaluator", "unavailable")
	if err := g.Serve(lis); err != nil {
		log.Error("serve", "error", err)
		os.Exit(1)
	}
}

// recordAttrs maps a transaction record onto OTLP attributes. Keys follow the
// sandbox event schema and OTel semantic conventions where one exists.
func recordAttrs(r extproc.Record) map[string]any {
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
		"gateway.first_chunk_after_ms":  r.FirstChunkAfterMs,
		"gateway.watchdog_fired":        r.WatchdogFired,
		"gateway.early_eos":             r.EarlyEOS,
		"gen_ai.response.finish_reason": r.StopReason,
	}
	for k, v := range r.Attribution {
		a["gateway.attribution."+k] = v
	}
	if d := r.Decision; d != nil {
		a["policy.rule_id"] = d.RuleID
		a["policy.action"] = string(d.Action)
		a["policy.reason"] = d.Reason
		a["policy.class_version"] = d.ClassVersion
		a["policy.degraded"] = d.Degraded
		a["gen_ai.request.model"] = d.Model
	}
	return a
}
