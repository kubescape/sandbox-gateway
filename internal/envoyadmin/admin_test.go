package envoyadmin

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func serve(t *testing.T, mux *http.ServeMux) *Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "adm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })
	return New(sock)
}

func TestStats(t *testing.T) {
	mux := http.NewServeMux()
	var gotFilter string
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("filter")
		if r.URL.Query().Get("format") != "json" {
			http.Error(w, "want json", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"stats":[
			{"name":"http.egress_api_anthropic_com.downstream_cx_active","value":2},
			{"name":"http.egress_api_openai_com.downstream_cx_active","value":0},
			{"histograms":{"supported_quantiles":[]}}]}`))
	})
	c := serve(t, mux)
	got, err := c.Stats(context.Background(), `^http\.egress_`)
	if err != nil {
		t.Fatal(err)
	}
	if gotFilter != `^http\.egress_` {
		t.Fatalf("filter sent = %q", gotFilter)
	}
	if len(got) != 2 || got["http.egress_api_anthropic_com.downstream_cx_active"] != 2 {
		t.Fatalf("stats = %v", got)
	}
}

func TestServerInfo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/server_info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"c0ffee/1.40.2/Clean/RELEASE/BoringSSL","state":"LIVE"}`))
	})
	info, err := serve(t, mux).ServerInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "1.40.2" || !info.Live {
		t.Fatalf("info = %+v", info)
	}
}

func TestDownEnvoyIsAnError(t *testing.T) {
	c := New(filepath.Join(os.TempDir(), "no-such-envoy-admin.sock"))
	if _, err := c.Stats(context.Background(), "x"); err == nil {
		t.Fatal("want an error")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusServiceUnavailable) })
	if _, err := serve(t, mux).Stats(context.Background(), "x"); err == nil {
		t.Fatal("a non-200 answer is an error")
	}
}
