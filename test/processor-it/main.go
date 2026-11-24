// Command processor-it is the processor for the integration stack. It runs
// the same server as cmd/processor, but against an in-memory connection table
// and workload lookup, because the stack has no eBPF redirect and no
// node-agent: Envoy sees the test client's own address.
//
// By default every connection belongs to one fixed bound pod. With
// -reject-all no connection is in the table, so every request is refused.
// With -evaluator a test evaluator is registered that denies requests for
// the model "denied-model", in the mode -mode gives.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubescape/sandbox-gateway/internal/app"
	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/lookup"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

const cgroup = 4242

// stubTable answers every address with one connection, or none.
type stubTable struct {
	posture   string
	rejectAll bool
}

func (s stubTable) Conn(conntable.Key) (conntable.Conn, bool, error) {
	if s.rejectAll {
		return conntable.Conn{}, false, nil
	}
	return conntable.Conn{CgroupID: cgroup, PID: 1, BindingID: 1,
		OrigDst: netip.MustParseAddrPort("192.0.2.10:443")}, true, nil
}

func (s stubTable) Binding(id uint64) (conntable.Binding, bool, error) {
	if id != cgroup {
		return conntable.Binding{}, false, nil
	}
	return conntable.Binding{BindingID: 1, Posture: s.posture}, true, nil
}

func stubLookup(context.Context, uint64) (lookup.Workload, time.Time, error) {
	w := lookup.Workload{Namespace: "it", Pod: "it-pod", Container: "main", BindingID: 1}
	w.Controller.Kind, w.Controller.Name = "Deployment", "it"
	return w, time.Time{}, nil
}

func main() {
	cfg := app.Flags(flag.CommandLine)
	posture := flag.String("posture", conntable.PostureAllow, "fail posture of the stub pod: allow or deny")
	rejectAll := flag.Bool("reject-all", false, "no connection is in the table, so every request is refused")
	withEvaluator := flag.Bool("evaluator", false, "register a test evaluator that denies the model "+deniedModel)
	mode := flag.String("mode", plugin.ModeEnforce, "mode of the test evaluator's verdicts: audit or enforce")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	cfg.Log = log
	cfg.Conns = stubTable{posture: *posture, rejectAll: *rejectAll}
	cfg.Lookup = stubLookup
	if *withEvaluator {
		plugin.Register(testEvaluator{mode: *mode})
		cfg.Evaluator = plugin.Registered()
	}
	log.Warn("integration test build: stub connection table and lookup",
		"reject_all", *rejectAll, "posture", *posture, "evaluator", *withEvaluator, "mode", *mode)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := app.Run(ctx, *cfg); err != nil {
		log.Error("processor", "error", err)
		os.Exit(1)
	}
}
