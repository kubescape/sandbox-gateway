package ca

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"
)

func newTestMinter(t *testing.T, opts Options) (*Minter, *x509.Certificate) {
	t.Helper()
	cert, key, err := NewSelfSignedCA("test-ca", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return NewMinter(cert, key, opts), cert
}

func TestLeafVerifiesAgainstCA(t *testing.T) {
	m, caCert := newTestMinter(t, Options{})
	leaf, err := m.Leaf("API.Anthropic.com.")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	x, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := x.Verify(x509.VerifyOptions{DNSName: "api.anthropic.com", Roots: pool}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
	if len(pair.Certificate) != 2 {
		t.Fatalf("want leaf+CA chain, got %d certs", len(pair.Certificate))
	}
}

func TestLeafIsCached(t *testing.T) {
	m, _ := newTestMinter(t, Options{})
	a, _ := m.Leaf("api.anthropic.com")
	b, _ := m.Leaf("api.anthropic.com")
	if string(a.CertPEM) != string(b.CertPEM) {
		t.Fatal("second call minted a new leaf")
	}
}

func TestLeafRemintedPastHalfLife(t *testing.T) {
	now := time.Now()
	m, _ := newTestMinter(t, Options{LeafTTL: time.Hour, Now: func() time.Time { return now }})
	a, _ := m.Leaf("api.anthropic.com")
	now = now.Add(31 * time.Minute)
	b, _ := m.Leaf("api.anthropic.com")
	if string(a.CertPEM) == string(b.CertPEM) {
		t.Fatal("leaf past half-life was not re-minted")
	}
	if m.CacheLen() != 1 {
		t.Fatalf("cache len %d, want 1", m.CacheLen())
	}
}

// The SNI flood guard on our side: iterating names never grows the cache past its bound.
func TestCacheBoundedUnderSNIIteration(t *testing.T) {
	m, _ := newTestMinter(t, Options{CacheSize: 16})
	for i := 0; i < 500; i++ {
		if _, err := m.Leaf(fmt.Sprintf("h%d.flood.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := m.CacheLen(); got != 16 {
		t.Fatalf("cache len %d, want 16", got)
	}
}

func TestValidateSNI(t *testing.T) {
	m, _ := newTestMinter(t, Options{AllowSuffixes: []string{"anthropic.com", ".openai.com"}})
	cases := []struct {
		sni string
		ok  bool
	}{
		{"api.anthropic.com", true},
		{"anthropic.com", true},
		{"api.openai.com", true},
		{"evilanthropic.com", false},
		{"api.anthropic.com.evil.io", false},
		{"localhost", false},
		{"10.0.0.1", false},
		{"", false},
		{"-bad.anthropic.com", false},
		{"a_b.anthropic.com", false},
		{"x..anthropic.com", false},
	}
	for _, c := range cases {
		err := m.ValidateSNI(c.sni)
		if (err == nil) != c.ok {
			t.Errorf("ValidateSNI(%q) err=%v, want ok=%v", c.sni, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrSNIRejected) {
			t.Errorf("ValidateSNI(%q) error not ErrSNIRejected: %v", c.sni, err)
		}
	}
}

func TestLeafRejectsBadSNI(t *testing.T) {
	m, _ := newTestMinter(t, Options{})
	if _, err := m.Leaf("not a host"); !errors.Is(err, ErrSNIRejected) {
		t.Fatalf("got %v, want ErrSNIRejected", err)
	}
	if m.CacheLen() != 0 {
		t.Fatal("rejected SNI was cached")
	}
}

// Exact-host mode: subdomains of an allowed host are refused, unlike suffix mode.
func TestValidateSNIExactHosts(t *testing.T) {
	m, _ := newTestMinter(t, Options{AllowHosts: []string{"api.anthropic.com", "API.OpenAI.com"}})
	for sni, ok := range map[string]bool{
		"api.anthropic.com":         true,
		"api.openai.com":            true,
		"h1.api.anthropic.com":      false,
		"flood.anthropic.com":       false,
		"anthropic.com":             false,
		"api.anthropic.com.evil.io": false,
	} {
		if err := m.ValidateSNI(sni); (err == nil) != ok {
			t.Errorf("ValidateSNI(%q) err=%v, want ok=%v", sni, err, ok)
		}
	}
}

// Per-node intermediate: leaves minted by a node intermediate verify against the root
// alone (the chain the minter serves includes the intermediate); a different node's
// intermediate can't mint for this chain, and an expired intermediate breaks only its node.
func TestPerNodeIntermediate(t *testing.T) {
	root, rootKey, err := NewRootCA("root", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, interKey, err := NewIntermediate(root, rootKey, "node-a", 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMinter(inter, interKey, Options{})
	leaf, err := m.Leaf("api.anthropic.com")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) != 2 {
		t.Fatalf("chain has %d certs, want leaf + intermediate", len(pair.Certificate))
	}
	lc, _ := x509.ParseCertificate(pair.Certificate[0])
	ic, _ := x509.ParseCertificate(pair.Certificate[1])
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(ic)
	if _, err := lc.Verify(x509.VerifyOptions{DNSName: "api.anthropic.com", Roots: roots, Intermediates: inters}); err != nil {
		t.Fatalf("leaf via node intermediate does not verify against the root: %v", err)
	}
	// A leaf whose intermediate has expired fails verification, for that node only.
	if _, err := lc.Verify(x509.VerifyOptions{DNSName: "api.anthropic.com", Roots: roots, Intermediates: inters, CurrentTime: time.Now().Add(8 * 24 * time.Hour)}); err == nil {
		t.Fatal("leaf verified after its intermediate expired")
	}
}
