package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

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
