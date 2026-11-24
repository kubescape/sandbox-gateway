// Package processor is the whole processor program, for builds that add an
// evaluator. Such a build is a main package that imports its evaluator, which
// calls plugin.Register from an init function, and then calls Main:
//
//	package main
//
//	import (
//		_ "example.com/evaluator" // registers itself
//		"github.com/kubescape/sandbox-gateway/pkg/processor"
//	)
//
//	func main() { processor.Main() }
//
// cmd/processor is the same program with no evaluator imported.
package processor

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
	"github.com/kubescape/sandbox-gateway/internal/policysource"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// Main parses the flags, opens the kernel tables, and serves until SIGTERM
// or an interrupt, with the evaluator the build registered, if any. It exits
// the process when it cannot start.
func Main() {
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
	cfg.Evaluator = plugin.Registered()

	// The policy informers run with the pod's service account. The processor
	// runs as a pod and takes no kubeconfig.
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		log.Error("load the in-cluster config", "error", err)
		os.Exit(1)
	}
	client, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		log.Error("build the API client", "error", err)
		os.Exit(1)
	}
	cfg.Policies = policysource.New(client, time.Now)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := app.Run(ctx, *cfg); err != nil {
		log.Error("processor", "error", err)
		os.Exit(1)
	}
}
