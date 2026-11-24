// Command streamcheck is the integration check: one streamed Messages call
// through the gateway. It trusts only the CA it is given, so it passes only if
// the gateway terminated TLS with a leaf from that CA and the whole stream
// arrived. It prints a JSON summary and exits non-zero on any failure.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type result struct {
	Status     int    `json:"status"`
	Proto      string `json:"proto"`
	Issuer     string `json:"leaf_issuer"`
	Events     int    `json:"events"`
	Deltas     int    `json:"content_deltas"`
	StopReason string `json:"stop_reason"`
	Complete   bool   `json:"message_stop"`
	// Body is the start of the response body, kept with -expect-status.
	Body string `json:"body,omitempty"`
}

func main() {
	addr := flag.String("addr", "envoy:443", "gateway address")
	host := flag.String("host", "api.anthropic.com", "SNI and Host to ask for")
	caPath := flag.String("ca", "/certs/ca.crt", "the only CA to trust (PEM)")
	model := flag.String("model", "claude-haiku-5-5", "model in the request")
	wait := flag.Duration("wait", 60*time.Second, "keep retrying this long while the gateway starts; 0 tries once")
	hostHeader := flag.String("host-header", "", "send this Host header instead of -host, to check that the gateway refuses a mismatch")
	expect := flag.Int("expect-status", 0, "pass when the response has this status, without reading a stream")
	xff := flag.String("x-forwarded-for", "", "send this X-Forwarded-For header, to check that the gateway does not take the client's address from it")
	proxyLine := flag.String("proxy-header", "", "write this PROXY protocol v1 line before the TLS handshake, to check that the gateway does not accept one")
	flag.Parse()

	deadline := time.Now().Add(*wait)
	for {
		res, err := call(*addr, *host, *hostHeader, *caPath, *model, *xff, *proxyLine, *expect)
		if err == nil {
			_ = json.NewEncoder(os.Stdout).Encode(res)
			return
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "streamcheck:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "streamcheck: retrying:", err)
		time.Sleep(time.Second)
	}
}

func call(addr, host, hostHeader, caPath, model, xff, proxyLine string, expect int) (result, error) {
	var res result
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return res, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return res, fmt.Errorf("no certificate in %s", caPath)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{Transport: &http.Transport{
		// Every connection goes to the gateway, whatever the URL says. This
		// stands in for the redirect.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil || proxyLine == "" {
				return conn, err
			}
			if _, err := conn.Write([]byte(proxyLine + "\r\n")); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		},
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := fmt.Sprintf(`{"model":%q,"stream":true,"max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`, model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/v1/messages", strings.NewReader(body))
	if err != nil {
		return res, err
	}
	req.Header.Set("content-type", "application/json")
	if hostHeader != "" {
		req.Host = hostHeader
	}
	if xff != "" {
		req.Header.Set("x-forwarded-for", xff)
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer func() { _ = resp.Body.Close() }()
	res.Status, res.Proto = resp.StatusCode, resp.Proto
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		res.Issuer = resp.TLS.PeerCertificates[0].Issuer.CommonName
	}
	if expect != 0 {
		if resp.StatusCode != expect {
			return res, fmt.Errorf("status %d, want %d", resp.StatusCode, expect)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		res.Body = string(b)
		return res, nil
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("status %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	event := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
			res.Events++
			switch event {
			case "content_block_delta":
				res.Deltas++
			case "message_stop":
				res.Complete = true
			}
		case strings.HasPrefix(line, "data: ") && event == "message_delta":
			var d struct {
				Delta struct {
					StopReason string `json:"stop_reason"`
				} `json:"delta"`
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) == nil {
				res.StopReason = d.Delta.StopReason
			}
		}
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	if !res.Complete || res.Deltas == 0 || res.StopReason != "end_turn" {
		return res, errors.New("stream incomplete: " + fmt.Sprintf("%+v", res))
	}
	return res, nil
}
