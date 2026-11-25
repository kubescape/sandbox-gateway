package xds

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	listenerservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// afterSend, when set by a test, runs right after a response is sent. It
// lets a test land a Set in the gap between a send and the next wait.
var afterSend func()

// ListenerTypeURL is the xDS type of a Listener resource.
const ListenerTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"

// LDSStats are counters for the debug endpoint and the node status.
type LDSStats struct {
	Streams atomic.Int64 // open streams
	Pushes  atomic.Int64 // responses sent
	Acks    atomic.Int64
	Nacks   atomic.Int64 // responses Envoy rejected
}

// LDS serves the node's listeners to Envoy, state of the world: every
// response carries all of them.
//
// Nothing is sent before the first Set. Envoy's bootstrap waits for the first
// response without a timeout, so an Envoy that starts before the node
// controller knows the node opens no listener at all.
type LDS struct {
	listenerservicev3.UnimplementedListenerDiscoveryServiceServer
	log   *slog.Logger
	Stats LDSStats
	nonce atomic.Uint64

	mu        sync.Mutex
	resources []*anypb.Any
	version   string
	changed   chan struct{} // closed and remade on every new version
	acked     string        // last version an Envoy accepted
	rejected  string        // last version an Envoy refused, and why
	rejectMsg string
}

// NewLDS returns a server with no listeners yet.
func NewLDS(log *slog.Logger) *LDS {
	if log == nil {
		log = slog.Default()
	}
	return &LDS{log: log, changed: make(chan struct{})}
}

// Set replaces the listeners. It reports whether they differ from what was
// set before; when they do not, nothing is pushed.
func (s *LDS) Set(listeners ...*listenerv3.Listener) (changed bool, err error) {
	sorted := append([]*listenerv3.Listener(nil), listeners...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].GetName() < sorted[j].GetName() })
	h := fnv.New64a()
	resources := make([]*anypb.Any, 0, len(sorted))
	for _, l := range sorted {
		// Deterministic, so the version depends on the content and not on map order.
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(l)
		if err != nil {
			return false, err
		}
		_, _ = h.Write(raw)
		_, _ = h.Write([]byte{0})
		resources = append(resources, &anypb.Any{TypeUrl: ListenerTypeURL, Value: raw})
	}
	version := strconv.FormatUint(h.Sum64(), 16)
	s.mu.Lock()
	defer s.mu.Unlock()
	if version == s.version {
		return false, nil
	}
	s.resources, s.version = resources, version
	close(s.changed)
	s.changed = make(chan struct{})
	return true, nil
}

// Version returns the version set last, the last one an Envoy accepted, and
// the last one an Envoy refused with its reason.
func (s *LDS) Version() (current, acked, rejected, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, s.acked, s.rejected, s.rejectMsg
}

func (s *LDS) snapshot() (resources []*anypb.Any, version string, changed <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resources, s.version, s.changed
}

// StreamListeners is the state-of-the-world transport, the one the bootstrap
// uses.
func (s *LDS) StreamListeners(stream listenerservicev3.ListenerDiscoveryService_StreamListenersServer) error {
	s.Stats.Streams.Add(1)
	defer s.Stats.Streams.Add(-1)
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	reqs := make(chan *discoveryv3.DiscoveryRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case reqs <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	subscribed := false
	sent := "" // version last sent on this stream
	send := func(resources []*anypb.Any, version string) error {
		sent = version
		s.Stats.Pushes.Add(1)
		err := stream.Send(&discoveryv3.DiscoveryResponse{
			TypeUrl: ListenerTypeURL, VersionInfo: version, Resources: resources,
			Nonce: strconv.FormatUint(s.nonce.Add(1), 10),
		})
		if afterSend != nil {
			afterSend()
		}
		return err
	}
	for {
		// The resources, their version and the channel that the next Set
		// closes are read together, under one lock. A version set after the
		// last send is sent before waiting again, so a Set that lands between
		// a send and the wait is never missed.
		resources, version, changed := s.snapshot()
		if subscribed && version != "" && version != sent {
			if err := send(resources, version); err != nil {
				return err
			}
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case req := <-reqs:
			if t := req.GetTypeUrl(); t != "" && t != ListenerTypeURL {
				return status.Errorf(codes.InvalidArgument, "lds: type %q is not served here", t)
			}
			switch {
			case req.GetErrorDetail() != nil:
				s.Stats.Nacks.Add(1)
				msg := req.GetErrorDetail().GetMessage()
				s.mu.Lock()
				s.rejected, s.rejectMsg = sent, msg
				s.mu.Unlock()
				// Envoy keeps the listeners of the last version it accepted.
				s.log.Error("envoy rejected the listeners", "version", sent, "error", msg)
			case req.GetResponseNonce() != "":
				s.Stats.Acks.Add(1)
				s.mu.Lock()
				s.acked = req.GetVersionInfo()
				s.mu.Unlock()
			}
			subscribed = true
		case <-changed:
		}
	}
}

// FetchListeners is the unary form, for tests and tools.
func (s *LDS) FetchListeners(_ context.Context, _ *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	resources, version, _ := s.snapshot()
	if version == "" {
		return nil, status.Error(codes.Unavailable, "lds: no listeners yet")
	}
	return &discoveryv3.DiscoveryResponse{TypeUrl: ListenerTypeURL, VersionInfo: version, Resources: resources}, nil
}

// DeltaListeners is not served: the bootstrap asks for state of the world.
func (s *LDS) DeltaListeners(listenerservicev3.ListenerDiscoveryService_DeltaListenersServer) error {
	return status.Error(codes.Unimplemented, fmt.Sprintf("lds: only %s over the state-of-the-world stream is served", ListenerTypeURL))
}
