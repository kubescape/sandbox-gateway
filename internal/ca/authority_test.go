package ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newIssuer(t *testing.T, leafTTL, interTTL time.Duration, clk *fakeClock) (*Authority, *SelfSigned) {
	t.Helper()
	a := NewAuthority(leafTTL, clk.now)
	s, err := NewSelfSigned(a, nil, nil, interTTL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Issue(); err != nil {
		t.Fatal(err)
	}
	return a, s
}

// verify checks leaf for name the way a client that trusts only root would.
func verify(t *testing.T, leaf Leaf, name string, root *x509.Certificate, at time.Time) error {
	t.Helper()
	var certs []*x509.Certificate
	rest := leaf.CertPEM
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	if len(certs) != 2 {
		t.Fatalf("chain has %d certificates, want the leaf and the intermediate", len(certs))
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(certs[1])
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inters, CurrentTime: at})
	return err
}

func TestNoIntermediateNoLeaf(t *testing.T) {
	a := NewAuthority(time.Hour, nil)
	if _, err := a.Leaf("api.anthropic.com"); !errors.Is(err, ErrNoIntermediate) {
		t.Fatalf("err = %v", err)
	}
	if s := a.State(); s.CanDecrypt || !s.ValidUntil.IsZero() || s.RootFingerprint != "" {
		t.Fatalf("state = %+v", s)
	}
}

func TestLeafVerifiesThroughTheNodeIntermediate(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	a, issuer := newIssuer(t, time.Hour, 24*time.Hour, clk)
	leaf, err := a.Leaf("API.Anthropic.com.")
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, leaf, "api.anthropic.com", issuer.Root(), clk.t); err != nil {
		t.Fatalf("a client trusting only the root must accept the leaf: %v", err)
	}
	if err := verify(t, leaf, "api.openai.com", issuer.Root(), clk.t); err == nil {
		t.Fatal("the leaf is for one name only")
	}
	// Another node's root does not accept it.
	_, other := newIssuer(t, time.Hour, 24*time.Hour, clk)
	if err := verify(t, leaf, "api.anthropic.com", other.Root(), clk.t); err == nil {
		t.Fatal("a leaf must not verify against another root")
	}
	if got := leaf.NotAfter.Sub(clk.t); got != time.Hour {
		t.Fatalf("leaf lives %v, want 1h", got)
	}
}

func TestLeafIsRenewedAtHalfLife(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	a, _ := newIssuer(t, time.Hour, 24*time.Hour, clk)
	first, _ := a.Leaf("api.anthropic.com")
	clk.t = clk.t.Add(29 * time.Minute)
	if again, _ := a.Leaf("api.anthropic.com"); again.Serial != first.Serial {
		t.Fatal("before half its life the same leaf is served")
	}
	clk.t = clk.t.Add(2 * time.Minute)
	renewed, _ := a.Leaf("api.anthropic.com")
	if renewed.Serial == first.Serial || !renewed.NotAfter.After(first.NotAfter) {
		t.Fatal("past half its life the leaf is re-minted")
	}
}

func TestValidUntilMovesWithRenewals(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	a, _ := newIssuer(t, time.Hour, 24*time.Hour, clk)
	start := clk.t
	if s := a.State(); !s.ValidUntil.After(start.Add(23*time.Hour)) || !s.CanDecrypt {
		t.Fatalf("with no leaf the intermediate decides: %+v", s)
	}
	_, _ = a.Leaf("api.anthropic.com")
	clk.t = start.Add(10 * time.Minute)
	_, _ = a.Leaf("api.openai.com")
	if got := a.State().ValidUntil; !got.Equal(start.Add(time.Hour)) {
		t.Fatalf("valid until %v, want the older leaf's expiry %v", got, start.Add(time.Hour))
	}
	// Renewing the older leaf moves the time to the next earliest one.
	clk.t = start.Add(35 * time.Minute)
	_, _ = a.Leaf("api.anthropic.com")
	if got := a.State().ValidUntil; !got.Equal(start.Add(70 * time.Minute)) {
		t.Fatalf("valid until %v, want %v", got, start.Add(70*time.Minute))
	}
	a.Forget("api.openai.com")
	if got := a.State().ValidUntil; !got.Equal(start.Add(95 * time.Minute)) {
		t.Fatalf("after forgetting a name: %v", got)
	}
}

func TestReplacedIntermediateRemintsEverything(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	a, issuer := newIssuer(t, time.Hour, 24*time.Hour, clk)
	before, _ := a.Leaf("api.anthropic.com")
	fp := a.State().RootFingerprint
	replaced := a.Replaced()

	// Same root, new intermediate: every leaf changes, the fingerprint does not.
	if err := issuer.Issue(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-replaced:
	default:
		t.Fatal("Replaced must fire")
	}
	if len(a.Held()) != 0 {
		t.Fatal("a new intermediate drops every leaf")
	}
	after, _ := a.Leaf("api.anthropic.com")
	if after.Serial == before.Serial {
		t.Fatal("the leaf must be re-minted")
	}
	if err := verify(t, after, "api.anthropic.com", issuer.Root(), clk.t); err != nil {
		t.Fatal(err)
	}
	if a.State().RootFingerprint != fp {
		t.Fatal("the root did not change")
	}

	// A new root: the fingerprint changes with it.
	other, err := NewSelfSigned(a, nil, nil, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Issue(); err != nil {
		t.Fatal(err)
	}
	if got := a.State().RootFingerprint; got == fp || got != Fingerprint(other.Root()) {
		t.Fatalf("fingerprint = %s", got)
	}
	moved, _ := a.Leaf("api.anthropic.com")
	if verify(t, moved, "api.anthropic.com", issuer.Root(), clk.t) == nil {
		t.Fatal("a leaf under the new root must not verify against the old one")
	}
}

func TestCanDecryptTurnsFalseWhenTheIntermediateIsNotRenewed(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	a, issuer := newIssuer(t, time.Hour, 24*time.Hour, clk)
	clk.t = clk.t.Add(22*time.Hour + 30*time.Minute)
	if !a.State().CanDecrypt {
		t.Fatal("more than one leaf lifetime left")
	}
	clk.t = clk.t.Add(time.Hour)
	if a.State().CanDecrypt {
		t.Fatal("under one leaf lifetime left and no renewal: cannot decrypt")
	}
	// A leaf minted now ends with the intermediate, not an hour out.
	leaf, _ := a.Leaf("api.anthropic.com")
	if leaf.NotAfter.After(clk.t.Add(31 * time.Minute)) {
		t.Fatalf("leaf outlives its intermediate: %v", leaf.NotAfter.Sub(clk.t))
	}
	if err := issuer.Issue(); err != nil {
		t.Fatal(err)
	}
	if !a.State().CanDecrypt {
		t.Fatal("a renewal restores it")
	}
}
