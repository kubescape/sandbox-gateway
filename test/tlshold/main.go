// Command tlshold opens one TLS connection through the gateway, keeps it open
// and idle for a while, then sends a request on it. It prints "alive
// <status>" when the connection still answered, "dead <error>" when it did
// not.
//
// The integration test uses it to keep a filter chain busy while the
// listener is updated: a connection that Envoy drained answers nothing.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "envoy:18443", "gateway address")
	host := flag.String("host", "api.anthropic.com", "SNI and Host")
	caPath := flag.String("ca", "/certs/ca.crt", "the only CA to trust (PEM)")
	hold := flag.Duration("hold", 10*time.Second, "how long to keep the connection idle before the request")
	flag.Parse()

	pem, err := os.ReadFile(*caPath)
	if err != nil {
		fmt.Println("dead", err)
		os.Exit(1)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	// HTTP/1.1 only, so the request below is one plain exchange on this connection.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", *addr,
		&tls.Config{RootCAs: pool, ServerName: *host, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		fmt.Println("dead", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()
	fmt.Fprintln(os.Stderr, "tlshold: connected, holding", *hold)
	time.Sleep(*hold)

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /held HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", *host); err != nil {
		fmt.Println("dead", err)
		os.Exit(1)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		fmt.Println("dead", err)
		os.Exit(1)
	}
	_ = resp.Body.Close()
	fmt.Println("alive", resp.StatusCode)
}
