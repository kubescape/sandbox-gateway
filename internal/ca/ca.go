// Package ca holds the node's certificate authority: the intermediate the
// node signs with and the short-lived leaf certificates it mints per
// hostname. Sandboxed pods trust the root the intermediate chains to.
//
// Which names may have a leaf is not decided here. The host set decides, and
// the SDS server asks it before it asks for a leaf.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"time"
)

// Leaf is a minted certificate and its key, PEM encoded, ready for an SDS
// TlsCertificate.
type Leaf struct {
	CertPEM  []byte // leaf followed by the CA certificate
	KeyPEM   []byte
	NotAfter time.Time
	// Serial identifies this certificate. Two leaves for one name never share it.
	Serial string
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
	return newCA(cn, ttl, nil, nil, 1, time.Now())
}

// NewIntermediate issues a node intermediate (pathlen 0) signed by root.
func NewIntermediate(root *x509.Certificate, rootKey crypto.Signer, cn string, ttl time.Duration) (*x509.Certificate, crypto.Signer, error) {
	return newCA(cn, ttl, root, rootKey, 0, time.Now())
}

func newCA(cn string, ttl time.Duration, parent *x509.Certificate, parentKey crypto.Signer, pathLen int, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
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
