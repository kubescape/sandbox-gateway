package sds

import (
	"context"
	"net"
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
	return dialWith(t, ca.Options{AllowSuffixes: []string{"anthropic.com"}}, 0)
}

func dialWith(t *testing.T, opts ca.Options, renew time.Duration) (secretv3.SecretDiscoveryServiceClient, *Server) {
	t.Helper()
	caCert, caKey, err := ca.NewSelfSignedCA("test", time.Hour*48)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(ca.NewMinter(caCert, caKey, opts), nil)
	srv.RenewEvery = renew
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	secretv3.RegisterSecretDiscoveryServiceServer(g, srv)
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///buf",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return secretv3.NewSecretDiscoveryServiceClient(conn), srv
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

// Gap 4: a subscribed leaf is pushed again once the minter renews it.
func TestDeltaPushesRenewedLeaf(t *testing.T) {
	client, srv := dialWith(t, ca.Options{AllowSuffixes: []string{"anthropic.com"}, LeafTTL: 400 * time.Millisecond}, 50*time.Millisecond)
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
