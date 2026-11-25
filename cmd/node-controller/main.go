// Command node-controller is the gateway's control process on one node. It
// serves Envoy its listeners (LDS) and leaf certificates (SDS), keeps the
// node's host set from the policy objects and node-agent's DNS sightings,
// answers the certificate health path, holds the node's intermediate CA and
// writes the node's SandboxGatewayNodeStatus.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	listenerservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/kubescape/sandbox-gateway/internal/ca"
	"github.com/kubescape/sandbox-gateway/internal/controller"
	"github.com/kubescape/sandbox-gateway/internal/envoyadmin"
	"github.com/kubescape/sandbox-gateway/internal/gatewaysock"
	"github.com/kubescape/sandbox-gateway/internal/hostset"
	"github.com/kubescape/sandbox-gateway/internal/nodestatus"
	"github.com/kubescape/sandbox-gateway/internal/nodeview"
	"github.com/kubescape/sandbox-gateway/internal/runutil"
	"github.com/kubescape/sandbox-gateway/internal/sds"
	"github.com/kubescape/sandbox-gateway/internal/xds"
)

func main() {
	listen := flag.String("listen", "unix:///run/kubescape-sandbox/xds.sock", "gRPC address Envoy fetches listeners and certificates from: unix:///path or host:port")
	gatewaySock := flag.String("gateway-socket", "unix:///run/kubescape-sandbox/gateway.sock", "HTTP address for node-agent's DNS sightings (POST /v1/sightings) and the health listener's certificate path (GET /healthz/certs)")
	adminSock := flag.String("envoy-admin", "/run/sandbox-gateway/envoy-admin.sock", "Envoy's admin unix socket; read for open connections per hostname")
	processorHealth := flag.String("processor-health-socket", "/run/kubescape-sandbox/processor-health.sock", "the processor's health unix socket; read for the node status")
	node := flag.String("node-name", os.Getenv("NODE_NAME"), "name of the node this pod runs on (default $NODE_NAME)")
	viewFile := flag.String("view-file", "", "read pods and policy objects from this YAML file, not from the API server (test stacks)")
	nameCap := flag.Int("name-cap", 256, "most hostnames with a certificate and a filter chain on this node, exact and learned together")
	leafTTL := flag.Duration("leaf-ttl", time.Hour, "leaf validity; a leaf is renewed at half of it")
	renew := flag.Duration("renew-every", time.Minute, "how often each Envoy stream is checked for renewed leaves to push")
	interTTL := flag.Duration("intermediate-ttl", 24*time.Hour, "validity of the stand-in intermediate; replaced at half of it")
	port := flag.Uint("listener-port", 18443, "port of the redirect listener")
	healthPort := flag.Uint("health-port", 18444, "port of the health listener node-agent probes")
	decryptCluster := flag.String("decrypt-cluster", "dfp", "bootstrap cluster decrypted requests are routed to")
	passthroughCluster := flag.String("passthrough-cluster", "orig_dst", "bootstrap cluster passthrough connections are forwarded through")
	rootCert := flag.String("ca-cert", "", "root certificate (PEM) the stand-in intermediate is signed by; empty creates one in memory")
	rootKey := flag.String("ca-key", "", "key of -ca-cert (PEM)")
	genRoot := flag.Bool("gen-ca", false, "create the -ca-cert and -ca-key files if they do not exist (test stacks)")
	debug := flag.String("debug-addr", "", "debug HTTP address (/stats, /debug/vars); it has no authentication, so keep it on loopback; empty disables")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// The intermediate. Until the operator issues node intermediates, this
	// process signs its own from a stand-in root.
	root, rootSigner, err := standInRoot(*rootCert, *rootKey, *genRoot)
	if err != nil {
		fatal(log, "stand-in root", err)
	}
	authority := ca.NewAuthority(*leafTTL, nil)
	issuer, err := ca.NewSelfSigned(authority, root, rootSigner, *interTTL)
	if err != nil {
		fatal(log, "stand-in issuer", err)
	}
	if err := issuer.Issue(); err != nil {
		fatal(log, "issue intermediate", err)
	}
	log.Info("intermediate issued by the stand-in root", "root_fingerprint", authority.State().RootFingerprint)
	go issuer.Run(ctx, func(err error) { log.Error("renew intermediate", "error", err) })

	// The node view.
	var view nodeview.Source
	var client dynamic.Interface // nil with -view-file: no API server, so no status object
	if *viewFile != "" {
		if view, err = nodeview.LoadStatic(*viewFile, *node); err != nil {
			fatal(log, "view file", err)
		}
	} else {
		if *node == "" {
			fatal(log, "node name", errors.New("set -node-name or NODE_NAME"))
		}
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			fatal(log, "in-cluster config", err)
		}
		if client, err = dynamic.NewForConfig(restCfg); err != nil {
			fatal(log, "kubernetes client", err)
		}
		view = nodeview.NewInformers(client, *node)
	}
	go view.Run(ctx)

	admin := envoyadmin.New(*adminSock)
	activity := &controller.Activity{Stats: admin.Stats}
	set := hostset.NewNodeSet(*nameCap, activity.Busy)
	lds := xds.NewLDS(log)
	secrets := sds.New(sds.Gated{Allow: set.Contains, Leaves: authority}, log)
	secrets.RenewEvery = *renew
	ctrl := &controller.Controller{
		View: view, Set: set, Authority: authority, Listeners: lds, Activity: activity,
		KickSecrets: secrets.Kick, Log: log, NodeAddrs: localAddrs,
		Installed: func(ctx context.Context) ([]string, error) {
			return admin.InstalledChains(ctx, xds.EgressListener)
		},
		Config: xds.Config{Port: uint32(*port), HealthPort: uint32(*healthPort), DecryptCluster: *decryptCluster, PassthroughCluster: *passthroughCluster},
	}
	go ctrl.Run(ctx)

	// The node's status object, for the backend.
	if client != nil {
		status := &nodestatus.Writer{
			Client: client, Node: *node, Log: log,
			Sources: nodestatus.Sources{
				Envoy: admin.ServerInfo, Stats: admin.Stats, Processor: nodestatus.ProbeProcessor(*processorHealth),
				Hosts: set.Counts, Rejected: set.RejectedPatterns, Certs: authority.State,
			},
		}
		go status.Run(ctx)
	}

	// Sightings from node-agent.
	sock := &gatewaysock.Handler{Observe: set.Observe, Changed: ctrl.Kick, Log: log, Certs: func() gatewaysock.Certs {
		state := authority.State()
		c := gatewaysock.Certs{CanDecrypt: state.CanDecrypt, RootFingerprint: state.RootFingerprint}
		if !state.ValidUntil.IsZero() {
			until := state.ValidUntil.UTC()
			c.DecryptValidUntil = &until
		}
		return c
	}}
	gl, err := runutil.Listen(*gatewaySock)
	if err != nil {
		fatal(log, "listen "+*gatewaySock, err)
	}
	go func() {
		srv := &http.Server{Handler: sock.Mux(), ReadHeaderTimeout: 5 * time.Second}
		if err := srv.Serve(gl); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("gateway socket", "error", err)
		}
	}()

	runutil.ServeDebug(*debug, func() any {
		current, acked, rejected, reason := lds.Version()
		state := authority.State()
		return map[string]any{
			"hosts":            set.Counts(),
			"names":            set.Names(),
			"rejected":         set.RejectedPatterns(),
			"view_synced":      view.Synced(),
			"reconciles":       ctrl.Reconciles.Load(),
			"reconcile_errors": ctrl.Errors.Load(),
			"sightings":        sock.Sightings.Load(),
			"lds":              map[string]any{"version": current, "acked": acked, "rejected": rejected, "reject_reason": reason, "pushes": lds.Stats.Pushes.Load(), "nacks": lds.Stats.Nacks.Load()},
			"sds":              secrets.Snapshot(),
			"certs":            map[string]any{"can_decrypt": state.CanDecrypt, "valid_until": state.ValidUntil, "root_fingerprint": state.RootFingerprint, "leaves": len(authority.Held())},
		}
	})

	lis, err := runutil.Listen(*listen)
	if err != nil {
		fatal(log, "listen "+*listen, err)
	}
	g := grpc.NewServer()
	listenerservicev3.RegisterListenerDiscoveryServiceServer(g, lds)
	secretv3.RegisterSecretDiscoveryServiceServer(g, secrets)
	go func() {
		<-ctx.Done()
		g.Stop()
	}()
	log.Info("node controller listening", "xds", *listen, "gateway_socket", *gatewaySock, "node", *node, "name_cap", *nameCap)
	if err := g.Serve(lis); err != nil {
		fatal(log, "serve", err)
	}
}

// localAddrs returns the addresses of this network namespace's interfaces. The
// gateway pod is on the host network, so these are the node's own addresses.
func localAddrs() []netip.Addr {
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifaddrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if addr, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out
}

// standInRoot loads the root the stand-in intermediate is signed by. With no
// path it returns nil, and the issuer makes a root in memory.
func standInRoot(certPath, keyPath string, generate bool) (*x509.Certificate, crypto.Signer, error) {
	if certPath == "" {
		return nil, nil, nil
	}
	if generate {
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			cert, key, err := ca.NewRootCA("Kubescape Sandbox Gateway stand-in root", 30*24*time.Hour)
			if err != nil {
				return nil, nil, err
			}
			if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
				return nil, nil, err
			}
			if err := ca.WriteCA(cert, key, certPath, keyPath); err != nil {
				return nil, nil, err
			}
		}
	}
	return ca.LoadCA(certPath, keyPath)
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, "error", err)
	os.Exit(1)
}
