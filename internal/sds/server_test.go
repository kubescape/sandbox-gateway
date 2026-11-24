package sds

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/kubescape/sandbox-gateway/internal/ca"
)

func dial(t *testing.T) (secretv3.SecretDiscoveryServiceClient, *Server) {
	c, srv, _ := dialWith(t, time.Hour, 0)
	return c, srv
}

// dialWith starts a server over an authority with a stand-in intermediate. The
// gate allows names under anthropic.com, as a host set would.
func dialWith(t *testing.T, leafTTL, renew time.Duration) (secretv3.SecretDiscoveryServiceClient, *Server, *ca.SelfSigned) {
	t.Helper()
	authority := ca.NewAuthority(leafTTL, nil)
	issuer, err := ca.NewSelfSigned(authority, nil, nil, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Issue(); err != nil {
		t.Fatal(err)
	}
	srv := New(Gated{Allow: func(n string) bool { return strings.HasSuffix(n, ".anthropic.com") }, Leaves: authority}, nil)
	srv.RenewEvery = renew
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	secretv3.RegisterSecretDiscoveryServiceServer(g, srv)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///buf",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return secretv3.NewSecretDiscoveryServiceClient(conn), srv, issuer
}

func TestDeltaMintsAndRefuses(t *testing.T) {
	client, srv := dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := client.DeltaSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                SecretTypeURL,
		ResourceNamesSubscribe: []string{"api.anthropic.com", "evil.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Resources) != 1 || resp.Resources[0].Name != "api.anthropic.com" {
		t.Fatalf("resources = %v", resp.Resources)
	}
	if len(resp.RemovedResources) != 1 || resp.RemovedResources[0] != "evil.example.com" {
		t.Fatalf("removed = %v", resp.RemovedResources)
	}
	var sec tlsv3.Secret
	if err := resp.Resources[0].Resource.UnmarshalTo(&sec); err != nil {
		t.Fatal(err)
	}
	if len(sec.GetTlsCertificate().GetCertificateChain().GetInlineBytes()) == 0 {
		t.Fatal("empty certificate chain")
	}
	if got := srv.Snapshot(); got["minted"] != 1 || got["rejected"] != 1 {
		t.Fatalf("stats = %v", got)
	}
}

func TestSotWAckIsNotAnswered(t *testing.T) {
	client, _ := dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := client.StreamSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"api.anthropic.com"}
	if err := st.Send(&discoveryv3.DiscoveryRequest{TypeUrl: SecretTypeURL, ResourceNames: names}); err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Resources) != 1 {
		t.Fatalf("got %d resources", len(first.Resources))
	}
	// ACK, then a new subscription. The next response must be for the new set,
	// which proves the ACK produced no response of its own.
	if err := st.Send(&discoveryv3.DiscoveryRequest{TypeUrl: SecretTypeURL, ResourceNames: names,
		VersionInfo: first.VersionInfo, ResponseNonce: first.Nonce}); err != nil {
		t.Fatal(err)
	}
	names = append(names, "claude.anthropic.com")
	if err := st.Send(&discoveryv3.DiscoveryRequest{TypeUrl: SecretTypeURL, ResourceNames: names,
		VersionInfo: first.VersionInfo, ResponseNonce: first.Nonce}); err != nil {
		t.Fatal(err)
	}
	second, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Resources) != 2 {
		t.Fatalf("second response has %d resources, want 2", len(second.Resources))
	}
}

// A subscribed leaf is pushed again once it is renewed, with no request.
func TestDeltaPushesRenewedLeaf(t *testing.T) {
	client, srv, _ := dialWith(t, 400*time.Millisecond, 50*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := client.DeltaSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: SecretTypeURL, ResourceNamesSubscribe: []string{"api.anthropic.com"}}); err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.Recv() // pushed without any request, after half the TTL
	if err != nil {
		t.Fatal(err)
	}
	if first.Resources[0].Version == second.Resources[0].Version {
		t.Fatalf("renewal pushed the same version %s", first.Resources[0].Version)
	}
	if srv.Snapshot()["renewed"] < 1 {
		t.Fatal("renewed counter not bumped")
	}
}

// A new intermediate re-mints every leaf. Kick pushes them at once, without
// waiting for the renewal timer.
func TestKickPushesLeavesOfANewIntermediate(t *testing.T) {
	client, srv, issuer := dialWith(t, time.Hour, 0) // no timer: only Kick can push
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := client.DeltaSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: SecretTypeURL, ResourceNamesSubscribe: []string{"api.anthropic.com"}}); err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Issue(); err != nil {
		t.Fatal(err)
	}
	srv.Kick()
	second, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if first.Resources[0].Version == second.Resources[0].Version {
		t.Fatal("the leaf of the new intermediate must be a new version")
	}
	var a, b tlsv3.Secret
	_ = first.Resources[0].Resource.UnmarshalTo(&a)
	_ = second.Resources[0].Resource.UnmarshalTo(&b)
	if string(a.GetTlsCertificate().GetCertificateChain().GetInlineBytes()) == string(b.GetTlsCertificate().GetCertificateChain().GetInlineBytes()) {
		t.Fatal("the chain must carry the new intermediate")
	}
}
