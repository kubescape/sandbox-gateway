// Command processor is the gateway's Envoy external processor (ext_proc). It
// attributes each request to a pod from the kernel connection table and
// node-agent's workload lookup, parses AI provider traffic and records it. No
// rule evaluator is wired in here (see pkg/plugin), so it makes no decisions.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubescape/sandbox-gateway/internal/app"
	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/lookup"
)

func main() {
	cfg := app.Flags(flag.CommandLine)
	mapsDir := flag.String("maps-dir", conntable.DefaultDir, "directory where node-agent pins the conns and bindings maps")
	lookupSocket := flag.String("lookup-socket", lookup.DefaultSocket, "node-agent's workload lookup socket")
	lookupRefresh := flag.Duration("lookup-refresh", 5*time.Second, "ask node-agent again after a cached workload is this old")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	cfg.Log = log

	// Without the kernel tables no request can be attributed, so the
	// processor does not start. The lookup socket is not checked here: a
	// node-agent restart must not stop the processor, and lookups are cached.
	conns, err := conntable.Open(*mapsDir)
	if err != nil {
		log.Error("open the connection tables", "error", err)
		os.Exit(1)
	}
	cfg.Conns = conns
	cfg.Lookup = lookup.New(*lookupSocket, *lookupRefresh, time.Now).Workload

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := app.Run(ctx, *cfg); err != nil {
		log.Error("processor", "error", err)
		os.Exit(1)
	}
}
