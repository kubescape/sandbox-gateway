package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const c2Body = `{"namespace":"agents","pod":"coder-7d9f","container":"main",
 "controller":{"kind":"Deployment","name":"coder"},
 "bindingId":12,"policies":[{"uid":"uid-a","generation":4},{"uid":"uid-b","generation":1}]}`

// fakeAgent serves the workload lookup on a unix socket.
type fakeAgent struct {
	sock  string
	srv   *http.Server
	hits  atomic.Int64
	query atomic.Value // last raw query
	body  atomic.Value // response body; "" means 404
	fail  atomic.Bool  // answer 500
	hold  atomic.Value // chan struct{}: when set, a request waits for it to close
}

// block makes every request wait until the returned func is called.
func (a *fakeAgent) block() (release func()) {
	ch := make(chan struct{})
	a.hold.Store(ch)
	return func() { close(ch) }
}

// waitHits waits until the agent has seen n requests.
func (a *fakeAgent) waitHits(t *testing.T, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for a.hits.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("agent saw %d requests, want %d", a.hits.Load(), n)
		}
		runtime.Gosched()
	}
}

func newAgent(t *testing.T) *fakeAgent {
	t.Helper()
	dir, err := os.MkdirTemp("", "lk") // short: unix socket paths are limited to ~100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	a := &fakeAgent{sock: filepath.Join(dir, "lookup.sock")}
	a.body.Store(c2Body)
	a.start(t)
	t.Cleanup(a.stop)
	return a
}

func (a *fakeAgent) start(t *testing.T) {
	t.Helper()
	lis, err := net.Listen("unix", a.sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/workload", func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		a.query.Store(r.URL.RawQuery)
		if ch, ok := a.hold.Load().(chan struct{}); ok {
			select {
			case <-ch:
			case <-r.Context().Done():
				return
			}
		}
		if a.fail.Load() {
			http.Error(w, "broken", http.StatusInternalServerError)
			return
		}
		body := a.body.Load().(string)
		if body == "" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	})
	a.srv = &http.Server{Handler: mux}
	go func() { _ = a.srv.Serve(lis) }()
}

func (a *fakeAgent) stop() { _ = a.srv.Close(); _ = os.Remove(a.sock) }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)} }

func TestDecodesC2(t *testing.T) {
	a := newAgent(t)
	c := New(a.sock, 5*time.Second, time.Now)
	w, failing, err := c.Workload(context.Background(), 4711)
	if err != nil || !failing.IsZero() {
		t.Fatalf("%v %v", failing, err)
	}
	if w.Namespace != "agents" || w.Pod != "coder-7d9f" || w.Container != "main" ||
		w.Controller.Kind != "Deployment" || w.Controller.Name != "coder" || w.BindingID != 12 {
		t.Fatalf("%+v", w)
	}
	if len(w.Policies) != 2 || w.Policies[0] != (PolicyRef{UID: "uid-a", Generation: 4}) || w.Policies[1] != (PolicyRef{UID: "uid-b", Generation: 1}) {
		t.Fatalf("policies = %+v", w.Policies)
	}
	if q := a.query.Load(); q != "cgroup=4711" {
		t.Fatalf("query = %v", q)
	}
}

func TestNotBound(t *testing.T) {
	a := newAgent(t)
	a.body.Store("")
	c := New(a.sock, 5*time.Second, time.Now)
	if _, _, err := c.Workload(context.Background(), 1); !errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v, want ErrNotBound", err)
	}
}

// Review focus: a pod unbound between two requests must stop being served
// from the cache.
func TestNotBoundDropsCachedEntry(t *testing.T) {
	a := newAgent(t)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	a.body.Store("")
	clk.advance(6 * time.Second)
	if _, _, err := c.Workload(context.Background(), 1); !errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v, want ErrNotBound", err)
	}
	a.stop()
	if _, _, err := c.Workload(context.Background(), 1); err == nil || errors.Is(err, ErrNotBound) {
		t.Fatalf("an unbound workload came back from the cache: %v", err)
	}
}

func TestCachedWithinRefresh(t *testing.T) {
	a := newAgent(t)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	for range 3 {
		if _, _, err := c.Workload(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		clk.advance(time.Second)
	}
	if n := a.hits.Load(); n != 1 {
		t.Fatalf("%d requests for three calls inside the refresh interval, want 1", n)
	}
	clk.advance(5 * time.Second)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if n := a.hits.Load(); n != 2 {
		t.Fatalf("%d requests after the interval passed, want 2", n)
	}
	// Another cgroup is another entry.
	if _, _, err := c.Workload(context.Background(), 2); err != nil || a.hits.Load() != 3 {
		t.Fatalf("hits = %d, err = %v", a.hits.Load(), err)
	}
}

func TestServesCacheWhenSocketDown(t *testing.T) {
	a := newAgent(t)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	a.stop()
	clk.advance(10 * time.Second)
	firstFailure := clk.now()
	w, failing, err := c.Workload(context.Background(), 1)
	if err != nil || w.Pod != "coder-7d9f" || !failing.Equal(firstFailure) {
		t.Fatalf("%+v failing=%v err=%v", w, failing, err)
	}
	clk.advance(4 * time.Minute)
	_, failing, err = c.Workload(context.Background(), 1)
	if err != nil || !failing.Equal(firstFailure) {
		t.Fatalf("failingSince moved to %v, want the first failure %v (err %v)", failing, firstFailure, err)
	}
}

func TestNoCacheNoSocket(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "missing.sock"), 5*time.Second, time.Now)
	w, _, err := c.Workload(context.Background(), 1)
	if err == nil || errors.Is(err, ErrNotBound) || w.Pod != "" {
		t.Fatalf("%+v %v", w, err)
	}
}

func TestRecoveryClearsFailingSince(t *testing.T) {
	a := newAgent(t)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	a.stop()
	clk.advance(10 * time.Second)
	if _, failing, _ := c.Workload(context.Background(), 1); failing.IsZero() {
		t.Fatal("no failure reported with the socket gone")
	}
	a.start(t)
	clk.advance(10 * time.Second)
	if _, failing, err := c.Workload(context.Background(), 1); err != nil || !failing.IsZero() {
		t.Fatalf("failing=%v err=%v after the socket came back", failing, err)
	}
}

func TestBadAnswerIsAFailure(t *testing.T) {
	a := newAgent(t)
	a.body.Store(`{"namespace":`)
	c := New(a.sock, 5*time.Second, time.Now)
	if _, _, err := c.Workload(context.Background(), 1); err == nil || errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v", err)
	}
}

// A failing socket is asked again once per retry interval, not by every
// request, and the cached answer is served in between.
func TestFailingSocketIsNotAskedOnEveryCall(t *testing.T) {
	a := newAgent(t)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	a.fail.Store(true)
	clk.advance(6 * time.Second)
	for range 3 {
		w, failing, err := c.Workload(context.Background(), 1)
		if err != nil || w.Pod != "coder-7d9f" || failing.IsZero() {
			t.Fatalf("%+v failing=%v err=%v", w, failing, err)
		}
	}
	if n := a.hits.Load(); n != 2 {
		t.Fatalf("%d requests, want 2: the first answer and one failed retry", n)
	}
	clk.advance(retryAfter)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if n := a.hits.Load(); n != 3 {
		t.Fatalf("%d requests after the retry interval, want 3", n)
	}
}

// The same holds with nothing cached: the error is returned without a new request.
func TestFailingSocketNothingCached(t *testing.T) {
	a := newAgent(t)
	a.fail.Store(true)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	for range 3 {
		if _, failing, err := c.Workload(context.Background(), 1); err == nil || failing.IsZero() {
			t.Fatalf("failing=%v err=%v", failing, err)
		}
	}
	if n := a.hits.Load(); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
	// Another cgroup is not held back by this one's failure.
	_, _, _ = c.Workload(context.Background(), 2)
	if n := a.hits.Load(); n != 2 {
		t.Fatalf("%d requests after asking for another cgroup, want 2", n)
	}
}

// Requests that arrive together for one cgroup share one fetch.
func TestOneFetchPerCgroupAtATime(t *testing.T) {
	a := newAgent(t)
	release := a.block()
	c := New(a.sock, 5*time.Second, time.Now)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, _, err := c.Workload(context.Background(), 1)
			if err == nil && w.Pod != "coder-7d9f" {
				err = fmt.Errorf("workload %+v", w)
			}
			errs <- err
		}()
	}
	a.waitHits(t, 1)
	release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := a.hits.Load(); n != 1 {
		t.Fatalf("%d requests for eight concurrent calls, want 1", n)
	}
}

// While one request refreshes an entry, the others get the cached answer at once.
func TestCachedAnswerServedWhileRefreshing(t *testing.T) {
	a := newAgent(t)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	clk.advance(6 * time.Second)
	release := a.block()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = c.Workload(context.Background(), 1)
	}()
	a.waitHits(t, 2)
	w, _, err := c.Workload(context.Background(), 1) // must not wait for release
	if err != nil || w.Pod != "coder-7d9f" {
		t.Fatalf("%+v %v", w, err)
	}
	release()
	<-done
	if n := a.hits.Load(); n != 2 {
		t.Fatalf("%d requests, want 2", n)
	}
}

// A caller that goes away mid-fetch says nothing about the socket.
func TestCancelledCallerIsNotASocketFailure(t *testing.T) {
	a := newAgent(t)
	clk := newClock()
	c := New(a.sock, 5*time.Second, clk.now)
	if _, _, err := c.Workload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	clk.advance(6 * time.Second)
	release := a.block()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for a.hits.Load() < 2 {
			runtime.Gosched()
		}
		cancel()
	}()
	w, failing, err := c.Workload(ctx, 1)
	if err != nil || w.Pod != "coder-7d9f" || !failing.IsZero() {
		t.Fatalf("%+v failing=%v err=%v", w, failing, err)
	}
	release()
	// No retry interval was started: the next call asks again and succeeds.
	if _, failing, err := c.Workload(context.Background(), 1); err != nil || !failing.IsZero() || a.hits.Load() != 3 {
		t.Fatalf("failing=%v err=%v hits=%d", failing, err, a.hits.Load())
	}
}

// Review: the retry interval must start when the failed fetch returns. A fetch
// that fails only at the client timeout (2s) used to start a 1s interval at the
// time it was sent, already over, so the next request fetched again and could
// wait on the socket again, even with a workload cached.
func TestRetryIntervalStartsWhenFetchReturns(t *testing.T) {
	for _, cached := range []bool{false, true} {
		a := newAgent(t)
		clk := newClock()
		c := New(a.sock, 5*time.Second, clk.now)
		hits := int64(0)
		if cached {
			if _, _, err := c.Workload(context.Background(), 1); err != nil {
				t.Fatal(err)
			}
			hits = 1
			clk.advance(6 * time.Second) // past refresh: the next call fetches
		}
		a.fail.Store(true)
		release := a.block()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _, _ = c.Workload(context.Background(), 1)
		}()
		a.waitHits(t, hits+1)
		clk.advance(2 * time.Second) // the fetch is slow: longer than retryAfter
		release()
		<-done
		w, failing, err := c.Workload(context.Background(), 1)
		if n := a.hits.Load(); n != hits+1 {
			t.Fatalf("cached=%v: %d requests, want %d: the follow-up must wait out the interval", cached, n, hits+1)
		}
		if failing.IsZero() || (cached && (err != nil || w.Pod != "coder-7d9f")) || (!cached && err == nil) {
			t.Fatalf("cached=%v: %+v failing=%v err=%v", cached, w, failing, err)
		}
		clk.advance(retryAfter)
		_, _, _ = c.Workload(context.Background(), 1)
		if n := a.hits.Load(); n != hits+2 {
			t.Fatalf("cached=%v: %d requests after the interval, want %d", cached, n, hits+2)
		}
	}
}
