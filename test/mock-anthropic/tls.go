package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net/http"
	"time"
)

// serveTLS answers HTTPS with a self-signed leaf whose CN is "mock-internal", so a
// client can tell the mock answered directly rather than the gateway's MITM leaf.
func serveTLS(addr string, log *slog.Logger) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mock-internal"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"mock-internal"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	srv := &http.Server{Addr: addr, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	log.Info("mock-anthropic tls listening", "addr", addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Error("tls serve", "error", err)
	}
}
