package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"

	"github.com/kubescape/sandbox-gateway/internal/ca"
	"github.com/kubescape/sandbox-gateway/internal/hostset"
	"github.com/kubescape/sandbox-gateway/internal/nodeview"
	"github.com/kubescape/sandbox-gateway/internal/xds"
)

type fakeView struct {
	snap    nodeview.Snapshot
	synced  bool
	changed chan struct{}
}

func (v *fakeView) Snapshot() nodeview.Snapshot { return v.snap }
func (v *fakeView) Synced() bool                { return v.synced }
func (v *fakeView) Changed() <-chan struct{}    { return v.changed }
func (v *fakeView) Run(ctx context.Context)     { <-ctx.Done() }

// fakeListeners keeps what was set. ack copies the current version to acked,
// as an Envoy that accepted it would.
type fakeListeners struct {
	last    *listenerv3.Listener
	sets    int
	version int
	acked   int
}

func (f *fakeListeners) Set(ls ...*listenerv3.Listener) (bool, error) {
	f.last = ls[0]
	f.sets++
	f.version++
	return true, nil
}

func (f *fakeListeners) Version() (string, string, string, string) {
	v := func(n int) string {
		if n == 0 {
			return ""
		}
		return strings.Repeat("v", n)
	}
	return v(f.version), v(f.acked), "", ""
}

func (f *fakeListeners) ack() { f.acked = f.version }

func (f *fakeListeners) chains() []string {
	var out []string
	for _, fc := range f.last.GetFilterChains() {
		out = append(out, fc.GetName())
	}
	sort.Strings(out)
	return out
}

// mapped lists the names the matcher sends source to a decrypt chain for.
func (f *fakeListeners) mapped(source string) []string {
	on, ok := f.last.GetFilterChainMatcher().GetMatcherTree().GetExactMatchMap().GetMap()[source]
	if !ok {
		return nil
	}
	var out []string
	for name := range on.GetMatcher().GetMatcherTree().GetExactMatchMap().GetMap() {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type harness struct {
	c      *Controller
	view   *fakeView
	out    *fakeListeners
	active map[string]int64
	fail   error
	issuer *ca.SelfSigned
}

func newHarness(t *testing.T, cap int) *harness {
	t.Helper()
	h := &harness{view: &fakeView{synced: true, changed: make(chan struct{}, 1)}, out: &fakeListeners{}, active: map[string]int64{}}
	activity := &Activity{Stats: func(context.Context, string) (map[string]int64, error) {
		if h.fail != nil {
			return nil, h.fail
		}
		out := map[string]int64{}
		for name, n := range h.active {
			out["http."+xds.StatPrefix(name)+".downstream_cx_active"] = n
		}
		return out, nil
	}}
	authority := ca.NewAuthority(time.Hour, nil)
	issuer, err := ca.NewSelfSigned(authority, nil, nil, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Issue(); err != nil {
		t.Fatal(err)
	}
	h.issuer = issuer
	h.c = &Controller{
		View: h.view, Set: hostset.NewNodeSet(cap, activity.Busy), Authority: authority,
		Listeners: h.out, Activity: activity, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return h
}

func (h *harness) reconcile(t *testing.T) {
	t.Helper()
	if err := h.c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func podOf(name, addr string, exact ...string) nodeview.Pod {
	return nodeview.Pod{Namespace: "team", Name: name, Addrs: []netip.Addr{netip.MustParseAddr(addr)}, Exact: exact}
}

func TestNothingIsBuiltBeforeTheViewSynced(t *testing.T) {
	h := newHarness(t, 8)
	h.view.synced = false
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com")}
	h.reconcile(t)
	if h.out.sets != 0 {
		t.Fatal("a listener built from half a view would drop chains in use")
	}
	h.view.synced = true
	h.reconcile(t)
	if h.out.sets != 1 {
		t.Fatal("once synced the listener is built")
	}
}

func TestTwoPodsSharingAnAddressSpaceAreDecryptedOnlyForTheirOwnNames(t *testing.T) {
	h := newHarness(t, 8)
	h.view.snap.Pods = []nodeview.Pod{
		podOf("a", "10.0.0.1", "api.anthropic.com"),
		podOf("b", "10.0.0.2", "api.openai.com"),
	}
	h.reconcile(t)
	if got, want := h.out.chains(), []string{"decrypt/api.anthropic.com", "decrypt/api.openai.com", "passthrough"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("chains = %v", got)
	}
	// The host set is node-wide; the match is per pod.
	if got := h.out.mapped("10.0.0.1"); !reflect.DeepEqual(got, []string{"api.anthropic.com"}) {
		t.Fatalf("pod a is decrypted for %v", got)
	}
	if got := h.out.mapped("10.0.0.2"); !reflect.DeepEqual(got, []string{"api.openai.com"}) {
		t.Fatalf("pod b is decrypted for %v", got)
	}
	if got := h.c.Authority.Held(); len(got) != 2 {
		t.Fatalf("a leaf is minted before its chain is served, held = %v", got)
	}
}

func TestPassthroughHostIsNotDecryptedEvenWhenAnotherPodsPolicyNamesIt(t *testing.T) {
	h := newHarness(t, 8)
	pinned := podOf("pinned", "10.0.0.1", "api.anthropic.com", "api.openai.com")
	pinned.Passthrough = []string{"api.openai.com"}
	h.view.snap.Pods = []nodeview.Pod{pinned, podOf("b", "10.0.0.2", "api.openai.com")}
	h.reconcile(t)
	if got := h.out.mapped("10.0.0.1"); !reflect.DeepEqual(got, []string{"api.anthropic.com"}) {
		t.Fatalf("the pinned pod is decrypted for %v", got)
	}
	if got := h.out.mapped("10.0.0.2"); !reflect.DeepEqual(got, []string{"api.openai.com"}) {
		t.Fatalf("pod b is decrypted for %v", got)
	}
}

func TestABusyChainIsKeptAndAnIdleOneRemovedOnlyAfterEnvoyAccepted(t *testing.T) {
	h := newHarness(t, 8)
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com", "api.openai.com")}
	h.reconcile(t)
	h.out.ack()

	// The policy stops naming api.openai.com while a stream is on its chain.
	h.active["api.openai.com"] = 1
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com")}
	h.reconcile(t)
	if got := h.out.mapped("10.0.0.1"); !reflect.DeepEqual(got, []string{"api.anthropic.com"}) {
		t.Fatalf("new connections must stop being decrypted for it at once, got %v", got)
	}
	if !contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("the chain carries a stream and must stay")
	}
	h.out.ack()
	h.reconcile(t)
	if !contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("still busy, still there")
	}

	// The stream ends, but Envoy has not accepted the latest listener yet.
	h.active["api.openai.com"] = 0
	h.reconcile(t)
	if !contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("nothing is removed before Envoy accepted the listener that unmapped the name")
	}
	h.out.ack()
	h.reconcile(t)
	if contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("idle and unmapped: the chain goes")
	}
	if got := h.c.Authority.Held(); !reflect.DeepEqual(got, []string{"api.anthropic.com"}) {
		t.Fatalf("the leaf of a removed name is dropped, held = %v", got)
	}
}

func TestWithEnvoyUnreachableNothingIsRemoved(t *testing.T) {
	h := newHarness(t, 8)
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com", "api.openai.com")}
	h.reconcile(t)
	h.out.ack()
	h.fail = errors.New("admin socket gone")
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com")}
	for i := 0; i < 3; i++ {
		h.reconcile(t)
		h.out.ack()
	}
	if !contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("with no reading every name is busy")
	}
}

func TestCapHoldsWith300ExactHosts(t *testing.T) {
	h := newHarness(t, 256)
	var hosts []string
	for i := 0; i < 300; i++ {
		hosts = append(hosts, "h"+strings.Repeat("0", 3-len(itoa(i)))+itoa(i)+".example.com")
	}
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", hosts...)}
	h.reconcile(t)
	if got := len(h.out.chains()); got != 257 { // 256 names and passthrough
		t.Fatalf("%d chains", got)
	}
	if got := len(h.c.Authority.Held()); got != 256 {
		t.Fatalf("%d leaves minted, the cap is 256", got)
	}
	if got := len(h.out.mapped("10.0.0.1")); got != 256 {
		t.Fatalf("the pod is decrypted for %d names", got)
	}
	if c := h.c.Set.Counts(); c.OverCap != 44 {
		t.Fatalf("counts = %+v", c)
	}
}

func TestNoIntermediateMeansNoDecryptChains(t *testing.T) {
	h := newHarness(t, 8)
	h.c.Authority = ca.NewAuthority(time.Hour, nil) // nothing issued yet
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com")}
	h.reconcile(t)
	if got := h.out.chains(); !reflect.DeepEqual(got, []string{"passthrough"}) {
		t.Fatalf("chains = %v: without a certificate everything passes through", got)
	}
}

func TestRunReactsToAChangeAndToANewIntermediate(t *testing.T) {
	h := newHarness(t, 8)
	kicked := make(chan struct{}, 4)
	h.c.KickSecrets = func() { kicked <- struct{}{} }
	h.c.Every, h.c.Settle = time.Hour, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.c.Run(ctx); close(done) }()

	wait := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait("the first reconcile", func() bool { return h.c.Reconciles.Load() >= 1 })
	n := h.c.Reconciles.Load()
	h.c.Kick()
	wait("a reconcile after Kick", func() bool { return h.c.Reconciles.Load() > n })
	n = h.c.Reconciles.Load()
	h.view.changed <- struct{}{}
	wait("a reconcile after a view change", func() bool { return h.c.Reconciles.Load() > n })

	if err := h.issuer.Issue(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-kicked:
	case <-time.After(5 * time.Second):
		t.Fatal("a new intermediate must push the re-minted leaves")
	}
	cancel()
	<-done
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
