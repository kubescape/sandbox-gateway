package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"
)

// ErrNoIntermediate is returned while the node has no intermediate to sign
// with.
var ErrNoIntermediate = errors.New("ca: no intermediate certificate yet")

// Authority holds the node's intermediate CA and the leaves signed with it.
//
// The intermediate's key stays in this process's memory. Leaves are kept per
// name and re-minted once they are past half their life, so asking for a
// name's leaf on a timer is what renews it. Replacing the intermediate drops
// every leaf: the next request for a name is signed by the new one.
//
// Authority is safe for concurrent use.
type Authority struct {
	leafTTL time.Duration
	now     func() time.Time

	mu       sync.Mutex
	inter    *x509.Certificate
	key      crypto.Signer
	interPEM []byte
	rootFP   string
	leaves   map[string]Leaf
	replaced chan struct{} // closed and remade on every Replace
}

// NewAuthority returns an authority with no intermediate. leafTTL <= 0 means
// one hour; now nil means time.Now.
func NewAuthority(leafTTL time.Duration, now func() time.Time) *Authority {
	if leafTTL <= 0 {
		leafTTL = time.Hour
	}
	if now == nil {
		now = time.Now
	}
	return &Authority{leafTTL: leafTTL, now: now, leaves: map[string]Leaf{}, replaced: make(chan struct{})}
}

// Fingerprint is the SHA-256 of a certificate's DER form, in hex. The health
// path reports the root's.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Replace installs a new intermediate, signed by root, and drops every leaf.
func (a *Authority) Replace(inter *x509.Certificate, key crypto.Signer, root *x509.Certificate) {
	a.mu.Lock()
	a.inter, a.key = inter, key
	a.interPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw})
	a.rootFP = Fingerprint(root)
	a.leaves = map[string]Leaf{}
	close(a.replaced)
	a.replaced = make(chan struct{})
	a.mu.Unlock()
}

// Replaced returns a channel that is closed at the next Replace.
func (a *Authority) Replaced() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.replaced
}

// Leaf returns the leaf for name, minting one when there is none or the one
// held is past half its life. The certificate chain is the leaf followed by
// the intermediate; the root is what clients trust and is not sent.
//
// Leaf mints for any name it is given. The caller decides which names may
// have one.
func (a *Authority) Leaf(name string) (Leaf, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inter == nil {
		return Leaf{}, ErrNoIntermediate
	}
	now := a.now()
	if l, ok := a.leaves[name]; ok && now.Before(l.NotAfter.Add(-a.leafTTL/2)) {
		return l, nil
	}
	l, err := a.mint(name, now)
	if err != nil {
		return Leaf{}, err
	}
	a.leaves[name] = l
	return l, nil
}

// Forget drops the leaf held for name.
func (a *Authority) Forget(name string) {
	a.mu.Lock()
	delete(a.leaves, strings.ToLower(strings.TrimSuffix(name, ".")))
	a.mu.Unlock()
}

// Held returns the names a leaf is held for.
func (a *Authority) Held() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.leaves))
	for n := range a.leaves {
		out = append(out, n)
	}
	return out
}

func (a *Authority) mint(name string, now time.Time) (Leaf, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Leaf{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Leaf{}, err
	}
	notAfter := now.Add(a.leafTTL)
	if notAfter.After(a.inter.NotAfter) {
		notAfter = a.inter.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.inter, key.Public(), a.key)
	if err != nil {
		return Leaf{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Leaf{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return Leaf{
		CertPEM:  append(certPEM, a.interPEM...),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		NotAfter: notAfter,
		Serial:   serial.Text(16),
	}, nil
}

// State is what the certificate health path reports.
type State struct {
	// CanDecrypt is false when there is no intermediate, or the one held has
	// less than one leaf lifetime left: no renewal has arrived, and leaves
	// minted from here on live shorter than they should.
	CanDecrypt bool
	// ValidUntil is the earliest expiry among the leaves held and the
	// intermediate. Zero when there is no intermediate.
	ValidUntil time.Time
	// RootFingerprint names the root the intermediate chains to.
	RootFingerprint string
}

// State returns the authority's state now.
func (a *Authority) State() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inter == nil {
		return State{}
	}
	s := State{ValidUntil: a.inter.NotAfter, RootFingerprint: a.rootFP}
	for _, l := range a.leaves {
		if l.NotAfter.Before(s.ValidUntil) {
			s.ValidUntil = l.NotAfter
		}
	}
	s.CanDecrypt = a.inter.NotAfter.Sub(a.now()) >= a.leafTTL
	return s
}

// SelfSigned stands in for the operator until it issues node intermediates:
// it holds a root and signs this node's intermediate itself. The root is
// created in memory unless one is given.
type SelfSigned struct {
	authority *Authority
	root      *x509.Certificate
	rootKey   crypto.Signer
	ttl       time.Duration
}

// NewSelfSigned returns an issuer for authority. A nil root makes a new one
// that lives a year. ttl <= 0 means 24 hours.
func NewSelfSigned(authority *Authority, root *x509.Certificate, rootKey crypto.Signer, ttl time.Duration) (*SelfSigned, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if root == nil {
		var err error
		if root, rootKey, err = NewRootCA("Kubescape Sandbox Gateway stand-in root", 365*24*time.Hour); err != nil {
			return nil, err
		}
	}
	return &SelfSigned{authority: authority, root: root, rootKey: rootKey, ttl: ttl}, nil
}

// Root returns the root certificate clients have to trust.
func (s *SelfSigned) Root() *x509.Certificate { return s.root }

// Issue signs a new intermediate and installs it.
func (s *SelfSigned) Issue() error {
	inter, key, err := newCA("Kubescape Sandbox Gateway node intermediate", s.ttl, s.root, s.rootKey, 0, s.authority.now())
	if err != nil {
		return err
	}
	s.authority.Replace(inter, key, s.root)
	return nil
}

// Run issues a new intermediate at half the lifetime of the last one, until
// ctx ends. A failed issue is retried after a minute and reported to onError.
func (s *SelfSigned) Run(ctx context.Context, onError func(error)) {
	wait := s.ttl / 2
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := s.Issue(); err != nil {
			if onError != nil {
				onError(err)
			}
			wait = time.Minute
			continue
		}
		wait = s.ttl / 2
	}
}
