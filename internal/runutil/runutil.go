// Package runutil holds small helpers shared by the binaries.
package runutil

import (
	"encoding/json"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Listen accepts "unix:///path/to.sock" or "host:port".
//
// A unix socket is created with mode 0660. If SANDBOX_GATEWAY_SOCKET_GID is set, the socket's group
// is changed to it, so a client in that group (Envoy runs as uid/gid 101 in the official
// image) can connect without the socket being world-writable.
func Listen(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		_ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o660); err != nil {
			l.Close()
			return nil, err
		}
		if g := os.Getenv("SANDBOX_GATEWAY_SOCKET_GID"); g != "" {
			gid, err := strconv.Atoi(g)
			if err != nil {
				l.Close()
				return nil, fmt.Errorf("SANDBOX_GATEWAY_SOCKET_GID: %w", err)
			}
			if err := os.Chown(path, -1, gid); err != nil {
				l.Close()
				return nil, fmt.Errorf("chown socket: %w", err)
			}
		}
		return l, nil
	}
	return net.Listen("tcp", addr)
}

// ServeDebug serves /debug/vars (expvar) and /stats (the snapshot func) on addr.
func ServeDebug(addr string, snapshot func() any) { ServeDebugWith(addr, snapshot, nil) }

// ServeDebugWith is ServeDebug plus extra handlers, keyed by path.
func ServeDebugWith(addr string, snapshot func() any, extra map[string]http.HandlerFunc) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	for path, h := range extra {
		mux.HandleFunc(path, h)
	}
	mux.Handle("/debug/vars", expvar.Handler())
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			slog.Error("debug server", "error", err)
		}
	}()
}

// SplitList splits a comma-separated flag value, dropping empties.
func SplitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
