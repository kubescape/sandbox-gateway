package app

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/extproc"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

type emptyTable struct{}

func (emptyTable) Conn(conntable.Key) (conntable.Conn, bool, error) {
	return conntable.Conn{}, false, nil
}
func (emptyTable) Binding(uint64) (conntable.Binding, bool, error) {
	return conntable.Binding{}, false, nil
}

func TestRunNeedsATable(t *testing.T) {
	if err := Run(context.Background(), Config{Listen: "127.0.0.1:0"}); err == nil {
		t.Fatal("Run started without a connection table")
	}
}

// Run serves the shared server: an unknown connection is rejected, and the
// server stops when the context ends.
func TestRunServesAndStops(t *testing.T) {
	dir, err := os.MkdirTemp("", "app")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	records := filepath.Join(dir, "records.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Listen: "unix://" + sock, Conns: emptyTable{}, RecordsFile: records})
	}()

	var conn *grpc.ClientConn
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err = grpc.NewClient("passthrough:///p", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st, err := extprocv3.NewExternalProcessorClient(conn).Process(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	attrs, _ := structpb.NewStruct(map[string]any{"source.address": "10.0.0.5:4242"})
	if err := st.Send(&extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": attrs},
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":path", RawValue: []byte("/v1/messages")}}}}},
	}); err != nil {
		t.Fatal(err)
	}
	r, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if r.GetImmediateResponse().GetDetails() != "no_connection_entry" {
		t.Fatalf("response = %v", r)
	}
	_ = st.CloseSend()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	b, err := os.ReadFile(records)
	if err != nil || len(b) == 0 {
		t.Fatalf("no record written: %v", err)
	}
}

func TestRecordAttrsIdentity(t *testing.T) {
	a := RecordAttrs(extproc.Record{Ended: "eos", Identity: &extproc.Identity{
		Namespace: "agents", Pod: "p", Container: "c", ControllerKind: "Deployment", ControllerName: "d",
		Posture: "deny", ConnLocalAddr: "10.0.0.5", ConnLocalPort: 4242, OrigDst: "1.2.3.4:443",
	}})
	for k, want := range map[string]any{"namespace": "agents", "pod": "p", "container": "c", "controller_kind": "Deployment",
		"controller_name": "d", "fail_posture": "deny", "conn_local_addr": "10.0.0.5", "conn_local_port": 4242, "orig_dst": "1.2.3.4:443"} {
		if a[k] != want {
			t.Errorf("%s = %v, want %v", k, a[k], want)
		}
	}
}

type noopEval struct{}

func (noopEval) Classify(string, string, io.Reader) (string, string, bool) { return "", "", false }
func (noopEval) Evaluate(context.Context, plugin.Request) plugin.Verdict   { return plugin.Verdict{} }
func (noopEval) DenyResponse(string, plugin.Verdict) (int, http.Header, []byte) {
	return 403, nil, nil
}
func (noopEval) StreamError(string, string) []byte { return nil }

func TestEvaluatorUnavailableReported(t *testing.T) {
	srv := extproc.New(extproc.Config{Conns: emptyTable{}})
	if got := stats(srv, nil)["evaluator"]; got != "unavailable" {
		t.Fatalf("no evaluator: %v", got)
	}
	if got := stats(srv, noopEval{})["evaluator"]; got != "available" {
		t.Fatalf("with an evaluator: %v", got)
	}
	if _, ok := stats(srv, nil)["stuckEvaluatorCalls"]; !ok {
		t.Fatal("stats do not report stuck evaluator calls")
	}
}

// fakePolicies is a policy source whose sync the test controls, holding no
// objects.
type fakePolicies struct{ synced atomic.Bool }

func (f *fakePolicies) Resolve([]plugin.PolicyRef) ([]plugin.PolicySection, int, int) {
	return nil, 0, 0
}
func (f *fakePolicies) LostSince() time.Time    { return time.Time{} }
func (f *fakePolicies) Synced() bool            { return f.synced.Load() }
func (f *fakePolicies) Run(ctx context.Context) { <-ctx.Done() }

// boundTable says every connection is from one bound allow pod.
type boundTable struct{}

func (boundTable) Conn(conntable.Key) (conntable.Conn, bool, error) {
	return conntable.Conn{CgroupID: 7, BindingID: 1, OrigDst: netip.MustParseAddrPort("192.0.2.1:443")}, true, nil
}
func (boundTable) Binding(uint64) (conntable.Binding, bool, error) {
	return conntable.Binding{BindingID: 1, Posture: conntable.PostureAllow}, true, nil
}

// healthGet asks the health socket and returns the status and body.
func healthGet(t *testing.T, sock string) (int, map[string]any) {
	t.Helper()
	c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := c.Get("http://processor/healthz/processor")
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			return resp.StatusCode, body
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runWithHealth(t *testing.T, p PolicySource, conns conntable.Table) (grpcSock, healthSock string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "app")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	grpcSock, healthSock = filepath.Join(dir, "p.sock"), filepath.Join(dir, "h.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Listen: "unix://" + grpcSock, HealthSocket: "unix://" + healthSock,
			Conns: conns, Policies: p, DebugAddr: ""})
	}()
	t.Cleanup(func() { cancel(); <-done })
	return grpcSock, healthSock
}

func TestHealthFailsUntilFirstSync(t *testing.T) {
	p := &fakePolicies{}
	_, hs := runWithHealth(t, p, emptyTable{})
	if code, _ := healthGet(t, hs); code != http.StatusServiceUnavailable {
		t.Fatalf("before the sync: %d", code)
	}
	p.synced.Store(true)
	code, body := healthGet(t, hs)
	if code != http.StatusOK || body["evaluator"] != "unavailable" {
		t.Fatalf("after the sync: %d %v", code, body)
	}
	if _, ok := body["degradedDecisions"]; !ok {
		t.Fatalf("no degradedDecisions in %v", body)
	}
}

// A request from an allow pod with nothing cached is degraded, and the health
// body counts it.
func TestDegradedCounterInHealthBody(t *testing.T) {
	p := &fakePolicies{}
	p.synced.Store(true)
	gs, hs := runWithHealth(t, p, boundTable{})
	healthGet(t, hs) // up
	conn, err := grpc.NewClient("passthrough:///p", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", gs)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st, err := extprocv3.NewExternalProcessorClient(conn).Process(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	attrs, _ := structpb.NewStruct(map[string]any{"source.address": "10.0.0.5:4242"})
	if err := st.Send(&extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": attrs},
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":path", RawValue: []byte("/v1/messages")}}}, EndOfStream: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Recv(); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseSend()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, body := healthGet(t, hs)
		if body["degradedDecisions"] == float64(1) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("health body = %v", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
