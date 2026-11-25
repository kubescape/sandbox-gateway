package extproc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sync/atomic"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kubescape/sandbox-gateway/pkg/jsonscan"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// scanEval classifies by scanning the body with jsonscan, as a real
// evaluator does, and keeps nothing of it.
type scanEval struct{ model atomic.Value }

func (e *scanEval) Classify(_, _ string, body io.Reader) (string, string, bool) {
	f, _ := jsonscan.Fields(body, 256, "model")
	m, ok := f["model"]
	e.model.Store(m)
	return "anthropic", m, ok
}

func (e *scanEval) Evaluate(context.Context, plugin.Request) plugin.Verdict {
	return plugin.Verdict{Action: plugin.ActionAllow, Mode: plugin.ModeEnforce, Rule: "mem"}
}

func (e *scanEval) DenyResponse(string, plugin.Verdict) (int, http.Header, []byte) {
	return 403, nil, nil
}

func (e *scanEval) StreamError(string, string) []byte { return nil }

const memServerEnv = "EXTPROC_MEMORY_SERVER_SOCKET"

// TestMemoryServerProcess is the processor half of
// TestThirtyMiBPromptUnder16MiB, run in a child process so that the test
// client's own allocations are not counted. It serves until its stdin
// closes, sampling its heap every millisecond, then prints what it saw: the
// peak live heap (what the last GC found still reachable) and the peak
// HeapAlloc, which also counts garbage not collected yet.
func TestMemoryServerProcess(t *testing.T) {
	sock := os.Getenv(memServerEnv)
	if sock == "" {
		t.Skip("run by TestThirtyMiBPromptUnder16MiB")
	}
	e := &scanEval{}
	srv := New(Config{Evaluator: e, Conns: newTable(), Lookup: fixedLookup(testWorkload(), time.Time{}, nil),
		Emit: func(r Record) { fmt.Printf("RECORD %d\n", r.RequestBytes) }})
	lis, err := net.Listen("unix", sock)
	must(t, err)
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	go func() { _ = g.Serve(lis) }()

	live := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	runtime.GC()
	metrics.Read(live)
	baseLive := live[0].Value.Uint64()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	baseAlloc := ms.HeapAlloc
	var peakLive, peakAlloc uint64
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				metrics.Read(live)
				peakLive = max(peakLive, live[0].Value.Uint64())
				runtime.ReadMemStats(&m)
				peakAlloc = max(peakAlloc, m.HeapAlloc)
			}
		}
	}()
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
	close(stop)
	<-sampled
	g.Stop()
	m, _ := e.model.Load().(string)
	fmt.Printf("HEAP %d %d %d %d %s\n", baseLive, peakLive, baseAlloc, peakAlloc, m)
}

// A 30 MiB prompt goes through an enforce-mode evaluator that reads the whole
// body, while the processor's live heap grows by less than 16 MiB: the body
// is streamed through, never held. Live heap, not HeapAlloc: HeapAlloc also
// counts each chunk's short-lived copies until the next GC collects them, so
// its peak measures GC pacing (GOGC) rather than what the processor keeps.
// Both are logged.
func TestThirtyMiBPromptUnder16MiB(t *testing.T) {
	if os.Getenv(memServerEnv) != "" {
		t.Skip("this is the server process")
	}
	const (
		total = 30 << 20
		chunk = 64 << 10
		limit = 16 << 20
	)
	sock := filepath.Join(t.TempDir(), "p.sock")
	child := exec.Command(os.Args[0], "-test.run=^TestMemoryServerProcess$", "-test.v")
	child.Env = append(os.Environ(), memServerEnv+"="+sock)
	stdin, err := child.StdinPipe()
	must(t, err)
	stdout, err := child.StdoutPipe()
	must(t, err)
	child.Stderr = os.Stderr
	must(t, child.Start())
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	waitLine := func(prefix string) string {
		t.Helper()
		timeout := time.After(30 * time.Second)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("server process exited before %q", prefix)
				}
				if len(l) >= len(prefix) && l[:len(prefix)] == prefix {
					return l
				}
			case <-timeout:
				t.Fatalf("no %q from the server process", prefix)
			}
		}
	}
	waitLine("READY")

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	must(t, err)
	defer conn.Close()
	st, err := extprocv3.NewExternalProcessorClient(conn).Process(context.Background())
	must(t, err)

	var forwardedBytes atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			r, err := st.Recv()
			if err != nil {
				return
			}
			forwardedBytes.Add(int64(len(forwarded(r))))
		}
	}()

	must(t, st.Send(&extprocv3.ProcessingRequest{
		Attributes: srcAttrs(testSource),
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: hdrs(":method", "POST", ":path", "/v1/messages", ":authority", "api.anthropic.com")}}}))
	// One reused buffer: a JSON prompt whose content string fills 30 MiB.
	head := []byte(`{"model":"claude-mem","messages":[{"role":"user","content":"`)
	tail := []byte(`"}]}`)
	buf := make([]byte, chunk)
	for sent := 0; sent < total; {
		n := min(chunk, total-sent)
		for i := range buf[:n] {
			buf[i] = 'a'
		}
		if sent == 0 {
			copy(buf, head)
		}
		last := sent+n == total
		if last {
			copy(buf[n-len(tail):n], tail)
		}
		must(t, st.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: buf[:n], EndOfStream: last}}}))
		sent += n
	}
	deadline := time.Now().Add(30 * time.Second)
	for forwardedBytes.Load() < total && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	must(t, st.CloseSend())
	<-done
	if got := forwardedBytes.Load(); got != total {
		t.Fatalf("forwarded %d of %d bytes", got, total)
	}
	if rec := waitLine("RECORD "); rec != fmt.Sprintf("RECORD %d", total) {
		t.Fatalf("record: %s", rec)
	}
	must(t, stdin.Close())
	var baseLive, peakLive, baseAlloc, peakAlloc uint64
	var model string
	if _, err := fmt.Sscanf(waitLine("HEAP "), "HEAP %d %d %d %d %s", &baseLive, &peakLive, &baseAlloc, &peakAlloc, &model); err != nil {
		t.Fatal(err)
	}
	if model != "claude-mem" {
		t.Fatalf("Classify saw model %q: the evaluator did not read the body", model)
	}
	grew := int64(peakLive) - int64(baseLive)
	t.Logf("processor live heap: base %.1f MiB, peak %.1f MiB, growth %.1f MiB; HeapAlloc peak %.1f MiB over a %.1f MiB base",
		mib(baseLive), mib(peakLive), float64(grew)/(1<<20), mib(peakAlloc), mib(baseAlloc))
	if grew >= limit {
		t.Fatalf("heap grew %.1f MiB for a 30 MiB prompt, want under 16", float64(grew)/(1<<20))
	}
}

func mib(b uint64) float64 { return float64(b) / (1 << 20) }
