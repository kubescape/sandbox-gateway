// Package ca mints short-lived TLS leaf certificates per SNI, signed by the
// operator CA that sandboxed pods trust.
//
// The minter is the SDS server's back end. Two guards live here because the
// clients that pick SNI values are the untrusted agents we contain:
//
//   - ValidateSNI rejects names that are not plausible hostnames, and names
//     outside an optional suffix allowlist.
//   - The leaf cache is a bounded LRU, so SNI iteration cannot grow our heap.
//
// Neither guard bounds Envoy's own on-demand secret cache (envoyproxy/envoy#47350).
// Refusing a name here makes Envoy fail that handshake, which is what the SNI
// flood test checks.
package ca

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// Leaf is a minted certificate and its key, PEM encoded, ready for an SDS
// TlsCertificate.
type Leaf struct {
	CertPEM  []byte // leaf followed by the CA certificate
	KeyPEM   []byte
	NotAfter time.Time
}

// Options configure a Minter.
type Options struct {
	LeafTTL       time.Duration // validity of minted leaves; default 24h
	CacheSize     int           // max leaves kept; default 1024
	AllowSuffixes []string      // if non-empty, only SNIs ending in one of these are minted
	AllowHosts    []string      // if non-empty, only these exact SNIs are minted (checked before AllowSuffixes)
	// Allow, when set, replaces AllowHosts and AllowSuffixes: only SNIs it accepts are
	// minted. The SDS server sets it to a hostset (exact hosts plus pattern names seen in
	// DNS answers), so the allowlist can change while the server runs.
	Allow func(sni string) bool
	Now   func() time.Time
}

// Minter signs per-SNI leaves with one CA.
type Minter struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	caPEM  []byte
	opts   Options

	mu    sync.Mutex
	lru   *list.List // front = most recent; values are *entry
	index map[string]*list.Element
}

type entry struct {
	sni  string
	leaf Leaf
}

// ErrSNIRejected is returned for names that fail validation.
var ErrSNIRejected = errors.New("sni rejected")

// NewMinter builds a Minter from a CA certificate and key.
func NewMinter(caCert *x509.Certificate, caKey crypto.Signer, opts Options) *Minter {
	if opts.LeafTTL == 0 {
		opts.LeafTTL = 24 * time.Hour
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = 1024
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Minter{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
		opts:   opts,
		lru:    list.New(),
		index:  map[string]*list.Element{},
	}
}

// Leaf returns a cached leaf for sni or mints a new one.
func (m *Minter) Leaf(sni string) (Leaf, error) {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	if err := m.ValidateSNI(sni); err != nil {
		return Leaf{}, err
	}
	now := m.opts.Now()

	m.mu.Lock()
	if el, ok := m.index[sni]; ok {
		e := el.Value.(*entry)
		// Re-mint once a leaf is past half its life.
		if now.Before(e.leaf.NotAfter.Add(-m.opts.LeafTTL / 2)) {
			m.lru.MoveToFront(el)
			m.mu.Unlock()
			return e.leaf, nil
		}
	}
	m.mu.Unlock()

	leaf, err := m.mint(sni, now)
	if err != nil {
		return Leaf{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.index[sni]; ok {
		el.Value.(*entry).leaf = leaf
		m.lru.MoveToFront(el)
	} else {
		m.index[sni] = m.lru.PushFront(&entry{sni: sni, leaf: leaf})
		for m.lru.Len() > m.opts.CacheSize {
			old := m.lru.Back()
			m.lru.Remove(old)
			delete(m.index, old.Value.(*entry).sni)
		}
	}
	return leaf, nil
}

// CacheLen reports how many leaves are cached.
func (m *Minter) CacheLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lru.Len()
}

// ValidateSNI checks that sni is a plausible DNS hostname (RFC 1123 labels,
// at most 253 bytes, at least two labels, not an IP literal) and, when an
// allowlist is set, that it ends in an allowed suffix.
func (m *Minter) ValidateSNI(sni string) error {
	if sni == "" || len(sni) > 253 {
		return fmt.Errorf("%w: length %d", ErrSNIRejected, len(sni))
	}
	labels := strings.Split(sni, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: %q has one label", ErrSNIRejected, sni)
	}
	allDigits := true
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: bad label in %q", ErrSNIRejected, sni)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c == '-':
				allDigits = false
			case c >= '0' && c <= '9':
			default:
				return fmt.Errorf("%w: bad byte in %q", ErrSNIRejected, sni)
			}
		}
	}
	if allDigits {
		return fmt.Errorf("%w: %q looks like an IP", ErrSNIRejected, sni)
	}
	if m.opts.Allow != nil {
		if m.opts.Allow(sni) {
			return nil
		}
		return fmt.Errorf("%w: %q not in the host set", ErrSNIRejected, sni)
	}
	if len(m.opts.AllowHosts) > 0 {
		for _, h := range m.opts.AllowHosts {
			if sni == strings.ToLower(h) {
				return nil
			}
		}
		if len(m.opts.AllowSuffixes) == 0 {
			return fmt.Errorf("%w: %q not in host allowlist", ErrSNIRejected, sni)
		}
	}
	if len(m.opts.AllowSuffixes) == 0 {
		return nil
	}
	for _, s := range m.opts.AllowSuffixes {
		s = strings.ToLower(strings.TrimPrefix(s, "."))
		if sni == s || strings.HasSuffix(sni, "."+s) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q not in allowlist", ErrSNIRejected, sni)
}

func (m *Minter) mint(sni string, now time.Time) (Leaf, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Leaf{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Leaf{}, err
	}
	notAfter := now.Add(m.opts.LeafTTL)
	if notAfter.After(m.caCert.NotAfter) {
		notAfter = m.caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, key.Public(), m.caKey)
	if err != nil {
		return Leaf{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Leaf{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return Leaf{
		CertPEM:  append(certPEM, m.caPEM...),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		NotAfter: notAfter,
	}, nil
}

// NewSelfSignedCA creates a CA for tests and local runs.
func NewSelfSignedCA(cn string, ttl time.Duration) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Kubescape Sandbox Gateway"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// LoadCA reads a PEM CA certificate and PKCS#8 / EC / PKCS#1 key from disk.
func LoadCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, errors.New("ca cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("ca key: no PEM block")
	}
	var k any
	switch kb.Type {
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(kb.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	default:
		k, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	}
	if err != nil {
		return nil, nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("ca key is not a signer")
	}
	return cert, signer, nil
}

// WriteCA writes a CA certificate and key as PEM files.
func WriteCA(cert *x509.Certificate, key crypto.Signer, certPath, keyPath string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// NewRootCA creates a root that may sign one level of intermediates (pathlen 1), for the
// per-node intermediate model: the root stays with the operator, each node gets a
// short-lived intermediate, and a compromised node exposes only its own intermediate.
func NewRootCA(cn string, ttl time.Duration) (*x509.Certificate, crypto.Signer, error) {
	return newCA(cn, ttl, nil, nil, 1)
}

// NewIntermediate issues a node intermediate (pathlen 0) signed by root.
func NewIntermediate(root *x509.Certificate, rootKey crypto.Signer, cn string, ttl time.Duration) (*x509.Certificate, crypto.Signer, error) {
	return newCA(cn, ttl, root, rootKey, 0)
}

func newCA(cn string, ttl time.Duration, parent *x509.Certificate, parentKey crypto.Signer, pathLen int) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"Kubescape Sandbox Gateway"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(ttl),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLen: pathLen, MaxPathLenZero: pathLen == 0,
	}
	signer, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, key.Public(), signerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}
