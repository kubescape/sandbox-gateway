// Package sds serves leaf certificates to Envoy over the Secret Discovery
// Service.
//
// Each decrypt chain names one secret, the chain's hostname. Envoy subscribes
// when the chain is added, so no handshake waits on this server, and keeps
// the secret until a newer one is pushed. Both transports are served:
//
//   - Delta (preferred): a refused name goes back in removed_resources, so
//     Envoy fails that handshake at once.
//   - State of the world: a refused name is left out of the response. Envoy
//     then waits for initial_fetch_timeout before failing, so keep that short.
package sds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/kubescape/sandbox-gateway/internal/ca"
)

// SecretTypeURL is the xDS type of a Secret resource.
const SecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// LeafSource mints a certificate for a name. *ca.Authority satisfies it.
type LeafSource interface {
	Leaf(name string) (ca.Leaf, error)
}

// ErrNotInSet is returned for a name the host set does not hold.
var ErrNotInSet = errors.New("sds: name is not in the host set")

// Gated is a LeafSource that mints only for names Allow accepts. A name that
// arrives here came from a filter chain, so it should always be in the set;
// the gate holds when it is not.
type Gated struct {
	Allow  func(name string) bool
	Leaves LeafSource
}

// Leaf implements LeafSource.
func (g Gated) Leaf(name string) (ca.Leaf, error) {
	if !g.Allow(name) {
		return ca.Leaf{}, fmt.Errorf("%w: %q", ErrNotInSet, name)
	}
	return g.Leaves.Leaf(name)
}

// Stats are counters the debug endpoint exposes.
type Stats struct {
	Minted   atomic.Int64 // names answered with a certificate
	Rejected atomic.Int64 // names refused (bad SNI, not allowlisted, mint error)
	Nacks    atomic.Int64 // responses Envoy rejected
	Streams  atomic.Int64 // open streams
	Renewed  atomic.Int64 // leaves pushed because they were renewed
}

// Server implements SecretDiscoveryServiceServer.
type Server struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer
	leaves LeafSource
	log    *slog.Logger
	Stats  Stats
	nonce  atomic.Uint64
	// RenewEvery is how often each delta stream re-checks its subscribed names and
	// pushes any leaf the minter has renewed. Envoy asks for a secret once and keeps
	// it, so without this push a leaf expires in place. 0 disables it.
	RenewEvery time.Duration

	kickMu sync.Mutex
	kick   chan struct{} // closed and remade by Kick
}

// Kick makes every stream check its names for a newer leaf now, without
// waiting for the next RenewEvery tick. Call it after the intermediate was
// replaced.
func (s *Server) Kick() {
	s.kickMu.Lock()
	close(s.kick)
	s.kick = make(chan struct{})
	s.kickMu.Unlock()
}

func (s *Server) kicked() <-chan struct{} {
	s.kickMu.Lock()
	defer s.kickMu.Unlock()
	return s.kick
}

// New returns an SDS server backed by leaves.
func New(leaves LeafSource, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{leaves: leaves, log: log, kick: make(chan struct{})}
}

// secretFor builds the Secret resource for name, or returns an error if the
// name is refused.
func (s *Server) secretFor(name string) (*tlsv3.Secret, string, error) {
	leaf, err := s.leaves.Leaf(name)
	if err != nil {
		s.Stats.Rejected.Add(1)
		return nil, "", err
	}
	s.Stats.Minted.Add(1)
	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
			CertificateChain: &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: leaf.CertPEM}},
			PrivateKey:       &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: leaf.KeyPEM}},
		}},
	}, version(leaf), nil
}

// version names one leaf. The serial is unique per certificate; the expiry
// stands in for a source that sets none.
func version(leaf ca.Leaf) string {
	if leaf.Serial != "" {
		return leaf.Serial
	}
	return strconv.FormatInt(leaf.NotAfter.UnixNano(), 10)
}

func (s *Server) nextNonce() string { return strconv.FormatUint(s.nonce.Add(1), 10) }

// DeltaSecrets is the incremental transport. Each subscribe gets an answer:
// a certificate, or the name in removed_resources.
func (s *Server) DeltaSecrets(stream secretv3.SecretDiscoveryService_DeltaSecretsServer) error {
	s.Stats.Streams.Add(1)
	defer s.Stats.Streams.Add(-1)

	var mu sync.Mutex           // guards sent and stream.Send
	sent := map[string]string{} // subscribed name -> version last sent
	closed := false             // set under mu when the handler returns; no Send after that
	defer func() {
		mu.Lock()
		closed = true
		mu.Unlock()
	}()
	send := func(names []string, renewOnly bool) error {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return nil
		}
		resp := &discoveryv3.DeltaDiscoveryResponse{TypeUrl: SecretTypeURL, Nonce: s.nextNonce()}
		for _, name := range names {
			sec, version, err := s.secretFor(name)
			if err != nil {
				if !renewOnly {
					s.log.Info("sds refuse", "name", name, "error", err)
					resp.RemovedResources = append(resp.RemovedResources, name)
				}
				continue
			}
			if renewOnly && sent[name] == version {
				continue
			}
			res, err := anypb.New(sec)
			if err != nil {
				return err
			}
			if renewOnly {
				s.Stats.Renewed.Add(1)
			}
			sent[name] = version
			resp.Resources = append(resp.Resources, &discoveryv3.Resource{Name: name, Version: version, Resource: res})
		}
		if len(resp.Resources) == 0 && len(resp.RemovedResources) == 0 {
			return nil
		}
		return stream.Send(resp)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		var tick <-chan time.Time
		if s.RenewEvery > 0 {
			t := time.NewTicker(s.RenewEvery)
			defer t.Stop()
			tick = t.C
		}
		for {
			kicked := s.kicked()
			select {
			case <-done:
				return
			case <-tick:
			case <-kicked:
			}
			mu.Lock()
			names := make([]string, 0, len(sent))
			for n := range sent {
				names = append(names, n)
			}
			mu.Unlock()
			if err := send(names, true); err != nil {
				s.log.Warn("sds renew push", "error", err)
			}
		}
	}()

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if req.GetErrorDetail() != nil {
			s.Stats.Nacks.Add(1)
			s.log.Warn("sds delta nack", "nonce", req.GetResponseNonce(), "error", req.GetErrorDetail().GetMessage())
		}
		if gone := req.GetResourceNamesUnsubscribe(); len(gone) > 0 {
			mu.Lock()
			for _, n := range gone {
				delete(sent, n)
			}
			mu.Unlock()
		}
		if names := req.GetResourceNamesSubscribe(); len(names) > 0 {
			if err := send(names, false); err != nil {
				return err
			}
		}
	}
}

// StreamSecrets is the state-of-the-world transport.
func (s *Server) StreamSecrets(stream secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	s.Stats.Streams.Add(1)
	defer s.Stats.Streams.Add(-1)
	var lastSent string
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if req.GetErrorDetail() != nil {
			s.Stats.Nacks.Add(1)
			s.log.Warn("sds sotw nack", "nonce", req.GetResponseNonce(), "error", req.GetErrorDetail().GetMessage())
		}
		key := setKey(req.GetResourceNames())
		if req.GetResponseNonce() != "" && key == lastSent {
			continue // ACK of what we already sent
		}
		resp, err := s.sotwResponse(req.GetResourceNames())
		if err != nil {
			return err
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
		lastSent = key
	}
}

// FetchSecrets is the unary REST-style transport, handy for curl-free tests.
func (s *Server) FetchSecrets(_ context.Context, req *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	return s.sotwResponse(req.GetResourceNames())
}

func (s *Server) sotwResponse(names []string) (*discoveryv3.DiscoveryResponse, error) {
	resp := &discoveryv3.DiscoveryResponse{TypeUrl: SecretTypeURL, Nonce: s.nextNonce()}
	var versions []string
	for _, name := range names {
		sec, version, err := s.secretFor(name)
		if err != nil {
			s.log.Info("sds refuse", "name", name, "error", err)
			continue
		}
		res, err := anypb.New(sec)
		if err != nil {
			return nil, err
		}
		resp.Resources = append(resp.Resources, res)
		versions = append(versions, name+"@"+version)
	}
	sort.Strings(versions)
	resp.VersionInfo = fmt.Sprintf("%x", fnv(versions))
	return resp, nil
}

func setKey(names []string) string {
	c := append([]string(nil), names...)
	sort.Strings(c)
	return fmt.Sprint(c)
}

func fnv(parts []string) uint64 {
	h := uint64(14695981039346656037)
	for _, p := range parts {
		for i := 0; i < len(p); i++ {
			h ^= uint64(p[i])
			h *= 1099511628211
		}
		h ^= 0xff
	}
	return h
}

// Snapshot returns the counters as a map for the debug endpoint.
func (s *Server) Snapshot() map[string]int64 {
	return map[string]int64{
		"minted":   s.Stats.Minted.Load(),
		"rejected": s.Stats.Rejected.Load(),
		"nacks":    s.Stats.Nacks.Load(),
		"streams":  s.Stats.Streams.Load(),
		"renewed":  s.Stats.Renewed.Load(),
	}
}
