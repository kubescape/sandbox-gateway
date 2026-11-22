// Command node-controller serves per-SNI leaf certificates to Envoy over SDS.
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"

	"github.com/kubescape/sandbox-gateway/internal/ca"
	"github.com/kubescape/sandbox-gateway/internal/hostset"
	"github.com/kubescape/sandbox-gateway/internal/runutil"
	"github.com/kubescape/sandbox-gateway/internal/sds"
)

func main() {
	listen := flag.String("listen", "unix:///run/kubescape-sandbox/sds.sock", "gRPC listen address: unix:///path or host:port")
	caCert := flag.String("ca-cert", "/certs/ca.crt", "operator CA certificate (PEM)")
	caKey := flag.String("ca-key", "/certs/ca.key", "operator CA key (PEM)")
	genCA := flag.Bool("gen-ca", false, "create the CA files if they do not exist (local runs only)")
	allow := flag.String("allow-suffix", "", "comma-separated SNI suffix allowlist; empty allows any valid hostname")
	hosts := flag.String("allow-hosts", "", "comma-separated exact SNI allowlist (match Envoy's server_names gate); takes precedence over -allow-suffix")
	patterns := flag.String("host-patterns", "", "comma-separated host patterns from the compiled policy (decision #5): a matching name is minted only after it is observed in DNS answers (POST /observe)")
	learnedCap := flag.Int("learned-cap", 64, "max names learned through -host-patterns per node; least recently seen evicted")
	cacheSize := flag.Int("cache-size", 1024, "max leaves cached")
	ttl := flag.Duration("leaf-ttl", 24*time.Hour, "leaf validity")
	renew := flag.Duration("renew-every", time.Minute, "how often each Envoy stream is checked for renewed leaves to push (gap 4); 0 disables")
	debug := flag.String("debug-addr", ":9101", "debug HTTP address (/stats, /debug/vars); empty disables")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	if *genCA {
		if _, err := os.Stat(*caCert); os.IsNotExist(err) {
			cert, key, err := ca.NewSelfSignedCA("Kubescape Sandbox Gateway CA", 30*24*time.Hour)
			if err != nil {
				fatal(log, "generate CA", err)
			}
			_ = os.MkdirAll(filepath.Dir(*caCert), 0o755)
			if err := ca.WriteCA(cert, key, *caCert, *caKey); err != nil {
				fatal(log, "write CA", err)
			}
			log.Info("generated CA", "cert", *caCert)
		}
	}
	cert, key, err := ca.LoadCA(*caCert, *caKey)
	if err != nil {
		fatal(log, "load CA", err)
	}
	opts := ca.Options{LeafTTL: *ttl, CacheSize: *cacheSize, AllowSuffixes: runutil.SplitList(*allow), AllowHosts: runutil.SplitList(*hosts)}
	var set *hostset.Set
	if *patterns != "" {
		// Decision #5: the allowlist is a host set. Exact hosts always; pattern names only
		// after a DNS sighting. Envoy's listener is rebuilt from GET /hosts.
		set, err = hostset.New(runutil.SplitList(*hosts), runutil.SplitList(*patterns), *learnedCap)
		if err != nil {
			fatal(log, "host set", err)
		}
		opts.Allow = set.Contains
	}
	minter := ca.NewMinter(cert, key, opts)
	srv := sds.New(minter, log)
	srv.RenewEvery = *renew
	runutil.ServeDebugWith(*debug, func() any {
		s := srv.Snapshot()
		s["cache_len"] = int64(minter.CacheLen())
		if set != nil {
			s["hosts_learned"] = int64(set.Learned())
			s["hosts_evicted"] = int64(set.Evicted())
		}
		return s
	}, hostRoutes(set, log))

	lis, err := runutil.Listen(*listen)
	if err != nil {
		fatal(log, "listen", err)
	}
	g := grpc.NewServer()
	secretv3.RegisterSecretDiscoveryServiceServer(g, srv)
	log.Info("sds-server listening", "addr", *listen, "allow_suffix", *allow, "allow_hosts", *hosts)
	if err := g.Serve(lis); err != nil {
		fatal(log, "serve", err)
	}
}

// hostRoutes stand in for the node agent's DNS feed in the PoC:
//
//	POST /observe?name=h   a workload's DNS answer named h
//	GET  /hosts            the current exact list Envoy's listener is built from
func hostRoutes(set *hostset.Set, log *slog.Logger) map[string]http.HandlerFunc {
	if set == nil {
		return nil
	}
	return map[string]http.HandlerFunc{
		"/observe": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			changed := 0
			for _, n := range r.URL.Query()["name"] {
				if set.Observe(n) {
					changed++
				}
			}
			if changed > 0 {
				log.Info("host set changed", "added", changed, "learned", set.Learned(), "evicted", set.Evicted())
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"changed": changed, "learned": set.Learned()})
		},
		"/hosts": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(set.Hosts())
		},
	}
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, "error", err)
	os.Exit(1)
}
