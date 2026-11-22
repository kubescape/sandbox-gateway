// Command latbench drives AC4: the same streamed Messages request, direct to
// the mock's TLS listener and through the gateway (TLS MITM + ext_proc), on a
// fresh connection each time. For each run it times the TCP connect, the TLS
// handshake, time to first content delta (TTFT) from the request write, the gap
// between consecutive SSE events, and the total. It prints percentiles per path.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type sample struct {
	connect, handshake, ttft, total time.Duration
	gaps                            []time.Duration
}

func main() {
	n := flag.Int("n", 50, "runs per path")
	direct := flag.String("direct", "mock-anthropic:443", "direct TLS target")
	proxied := flag.String("proxied", "envoy:443", "gateway")
	flag.Parse()
	out := map[string]any{}
	for _, p := range []struct{ name, addr string }{{"direct", *direct}, {"proxied", *proxied}} {
		var ss []sample
		for i := 0; i < *n; i++ {
			s, err := run(p.addr)
			if err != nil {
				fmt.Fprintln(os.Stderr, p.name, err)
				continue
			}
			ss = append(ss, s)
		}
		out[p.name] = summarise(ss)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func run(addr string) (sample, error) {
	var s sample
	t0 := time.Now()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return s, err
	}
	defer raw.Close()
	s.connect = time.Since(t0)
	t1 := time.Now()
	c := tls.Client(raw, &tls.Config{ServerName: "api.anthropic.com", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // bench
	if err := c.Handshake(); err != nil {
		return s, err
	}
	s.handshake = time.Since(t1)
	body := `{"model":"claude-haiku-5-5","stream":true,"max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	t2 := time.Now()
	if err := req.Write(c); err != nil {
		return s, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	last := time.Time{}
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "event: ") {
			continue
		}
		now := time.Now()
		if s.ttft == 0 && line == "event: content_block_delta" {
			s.ttft = now.Sub(t2)
		}
		if !last.IsZero() {
			s.gaps = append(s.gaps, now.Sub(last))
		}
		last = now
	}
	s.total = time.Since(t2)
	return s, nil
}

func pct(d []time.Duration, p float64) float64 {
	if len(d) == 0 {
		return 0
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return float64(d[int(p*float64(len(d)-1))].Microseconds()) / 1000
}

func summarise(ss []sample) map[string]any {
	var con, hs, ttft, tot, gaps []time.Duration
	for _, s := range ss {
		con, hs, ttft, tot = append(con, s.connect), append(hs, s.handshake), append(ttft, s.ttft), append(tot, s.total)
		gaps = append(gaps, s.gaps...)
	}
	m := func(d []time.Duration) map[string]float64 {
		return map[string]float64{"p50_ms": pct(d, .5), "p90_ms": pct(d, .9), "p99_ms": pct(d, .99)}
	}
	return map[string]any{"runs": len(ss), "connect": m(con), "tls_handshake": m(hs), "ttft": m(ttft), "event_gap": m(gaps), "total": m(tot)}
}
