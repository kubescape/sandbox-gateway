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
}

func main() {
	addr := flag.String("addr", "envoy:443", "gateway address")
	host := flag.String("host", "api.anthropic.com", "SNI and Host to ask for")
	caPath := flag.String("ca", "/certs/ca.crt", "the only CA to trust (PEM)")
	model := flag.String("model", "claude-haiku-5-5", "model in the request")
	wait := flag.Duration("wait", 60*time.Second, "keep retrying this long while the gateway starts")
	flag.Parse()

	deadline := time.Now().Add(*wait)
	for {
		res, err := call(*addr, *host, *caPath, *model)
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

func call(addr, host, caPath, model string) (result, error) {
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
			return dialer.DialContext(ctx, network, addr)
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
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer func() { _ = resp.Body.Close() }()
	res.Status, res.Proto = resp.StatusCode, resp.Proto
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		res.Issuer = resp.TLS.PeerCertificates[0].Issuer.CommonName
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
