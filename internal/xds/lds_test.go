package xds

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	listenerservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startLDS(t *testing.T) (*LDS, listenerservicev3.ListenerDiscoveryService_StreamListenersClient) {
	t.Helper()
	// A short directory: a unix socket path is limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "lds")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "x.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewLDS(nil)
	g := grpc.NewServer()
	listenerservicev3.RegisterListenerDiscoveryServiceServer(g, srv)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := listenerservicev3.NewListenerDiscoveryServiceClient(conn).StreamListeners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return srv, stream
}

// responses is one stream's incoming side. A single goroutine reads the
// stream, so a wait that times out loses nothing.
type responses struct {
	stream listenerservicev3.ListenerDiscoveryService_StreamListenersClient
	ch     chan *discoveryv3.DiscoveryResponse
	errs   chan error
}

func reader(stream listenerservicev3.ListenerDiscoveryService_StreamListenersClient) *responses {
	r := &responses{stream: stream, ch: make(chan *discoveryv3.DiscoveryResponse, 8), errs: make(chan error, 1)}
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				r.errs <- err
				return
			}
			r.ch <- resp
		}
	}()
	return r
}

// within returns the next response, or nil when none arrives in d.
func (r *responses) within(d time.Duration) *discoveryv3.DiscoveryResponse {
	select {
	case resp := <-r.ch:
		return resp
	case <-r.errs:
		return nil
	case <-time.After(d):
		return nil
	}
}

func build(t *testing.T, names ...string) *listenerv3.Listener {
	t.Helper()
	l, err := Config{}.Egress(Input{Names: names, Pods: []PodNames{{Addrs: addrs("10.0.0.1"), Names: names}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNothingIsServedBeforeTheFirstSet(t *testing.T) {
	srv, stream := startLDS(t)
	in := reader(stream)
	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: ListenerTypeURL}); err != nil {
		t.Fatal(err)
	}
	if resp := in.within(300 * time.Millisecond); resp != nil {
		t.Fatal("an Envoy that asks before the node is known must be left waiting")
	}
	if changed, err := srv.Set(build(t, "api.anthropic.com")); err != nil || !changed {
		t.Fatalf("Set: %v %v", changed, err)
	}
	resp := in.within(5 * time.Second)
	if resp == nil || len(resp.GetResources()) != 1 || resp.GetVersionInfo() == "" || resp.GetNonce() == "" {
		t.Fatalf("response = %v", resp)
	}
}

func TestOnlyAChangeIsPushed(t *testing.T) {
	srv, stream := startLDS(t)
	in := reader(stream)
	_, _ = srv.Set(build(t, "api.anthropic.com"))
	_ = stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: ListenerTypeURL})
	first := in.within(5 * time.Second)
	if first == nil {
		t.Fatal("no first response")
	}
	// The ACK gets no answer.
	_ = stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: ListenerTypeURL, VersionInfo: first.GetVersionInfo(), ResponseNonce: first.GetNonce()})
	if changed, _ := srv.Set(build(t, "api.anthropic.com")); changed {
		t.Fatal("the same listener is not a change")
	}
	if resp := in.within(300 * time.Millisecond); resp != nil {
		t.Fatal("nothing changed, nothing should be pushed")
	}
	if _, acked, _, _ := srv.Version(); acked != first.GetVersionInfo() {
		t.Fatalf("acked = %q, want %q", acked, first.GetVersionInfo())
	}

	if changed, _ := srv.Set(build(t, "api.anthropic.com", "api.openai.com")); !changed {
		t.Fatal("a new chain is a change")
	}
	second := in.within(5 * time.Second)
	if second == nil || second.GetVersionInfo() == first.GetVersionInfo() {
		t.Fatalf("second = %v", second)
	}
}

func TestANackIsRecordedAndNotResent(t *testing.T) {
	srv, stream := startLDS(t)
	in := reader(stream)
	_, _ = srv.Set(build(t, "api.anthropic.com"))
	_ = stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: ListenerTypeURL})
	first := in.within(5 * time.Second)
	if first == nil {
		t.Fatal("no first response")
	}
	_ = stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: ListenerTypeURL, ResponseNonce: first.GetNonce(),
		ErrorDetail: &status.Status{Code: 3, Message: "bad listener"}})
	if resp := in.within(300 * time.Millisecond); resp != nil {
		t.Fatal("a rejected version must not be sent again")
	}
	_, _, rejected, reason := srv.Version()
	if rejected != first.GetVersionInfo() || reason != "bad listener" || srv.Stats.Nacks.Load() != 1 {
		t.Fatalf("rejected = %q (%q), nacks = %d", rejected, reason, srv.Stats.Nacks.Load())
	}
	// The next version still goes out.
	_, _ = srv.Set(build(t, "api.openai.com"))
	if resp := in.within(5 * time.Second); resp == nil {
		t.Fatal("a new version after a NACK must be pushed")
	}
}

func TestAnotherTypeIsRefused(t *testing.T) {
	_, stream := startLDS(t)
	_ = stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: "type.googleapis.com/envoy.config.cluster.v3.Cluster"})
	if _, err := stream.Recv(); err == nil {
		t.Fatal("want an error")
	}
}

// A Set that lands after a response was sent and before the stream waits for
// the next change must still reach Envoy, with no further request from it.
func TestASetBetweenSendAndWaitIsNotMissed(t *testing.T) {
	srv, stream := startLDS(t)
	in := reader(stream)
	_, _ = srv.Set(build(t, "api.anthropic.com"))
	var once bool
	afterSend = func() {
		if !once {
			once = true
			_, _ = srv.Set(build(t, "api.anthropic.com", "api.openai.com"))
		}
	}
	t.Cleanup(func() { afterSend = nil })
	_ = stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: ListenerTypeURL})
	first := in.within(5 * time.Second)
	if first == nil {
		t.Fatal("no first response")
	}
	// Envoy sends nothing more: no ACK, no new request.
	second := in.within(2 * time.Second)
	if second == nil {
		t.Fatal("the version set right after the first send was never pushed")
	}
	if current, _, _, _ := srv.Version(); second.GetVersionInfo() != current || current == first.GetVersionInfo() {
		t.Fatalf("pushed %s, current %s, first %s", second.GetVersionInfo(), current, first.GetVersionInfo())
	}
}
