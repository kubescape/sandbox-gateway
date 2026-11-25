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
	last    *listenerv3.Listener // the redirect listener
	health  *listenerv3.Listener
	sets    int
	version int
	acked   int
}

func (f *fakeListeners) Set(ls ...*listenerv3.Listener) (bool, error) {
	for _, l := range ls {
		switch l.GetName() {
		case xds.EgressListener:
			f.last = l
		case xds.HealthListener:
			f.health = l
		}
	}
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
	c       *Controller
	view    *fakeView
	out     *fakeListeners
	active  map[string]int64
	warming int64
	fail    error
	issuer  *ca.SelfSigned
	// duringStats runs while the connection counts are read.
	duringStats func()
}

func newHarness(t *testing.T, cap int) *harness {
	t.Helper()
	h := &harness{view: &fakeView{synced: true, changed: make(chan struct{}, 1)}, out: &fakeListeners{}, active: map[string]int64{}}
	activity := &Activity{Stats: func(context.Context, string) (map[string]int64, error) {
		if h.fail != nil {
			return nil, h.fail
		}
		if h.duringStats != nil {
			h.duringStats()
		}
		out := map[string]int64{"listener_manager.total_listeners_warming": h.warming}
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

func TestHealthListenerTakesOnNodeSourcesOnly(t *testing.T) {
	h := newHarness(t, 8)
	h.view.snap.OnNode = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.9")}
	h.c.NodeAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.10")} }
	h.reconcile(t)
	if h.out.health == nil {
		t.Fatal("no health listener was set")
	}
	sources := h.out.health.GetFilterChainMatcher().GetMatcherTree().GetExactMatchMap().GetMap()
	for _, want := range []string{"10.0.0.1", "10.0.0.9", "192.168.1.10", "127.0.0.1"} {
		if _, ok := sources[want]; !ok {
			t.Errorf("%s is on the node and must reach the health listener", want)
		}
	}
	if len(sources) != 4 {
		t.Fatalf("sources = %d, want exactly the four on-node addresses", len(sources))
	}
	if h.out.health.GetFilterChainMatcher().GetOnNoMatch() != nil {
		t.Fatal("a source that is not on the node must get no chain")
	}
}

// Finding: the counts that let a retired chain go must be read after Envoy
// acknowledged the listener that unmapped it. An ACK that lands while the
// counts are being read is not enough: those counts may predate it.
func TestAnAckDuringTheSampleDoesNotLetAChainGo(t *testing.T) {
	h := newHarness(t, 8)
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com", "api.openai.com")}
	h.reconcile(t)
	h.out.ack()
	// The policy drops api.openai.com: it is retired, the listener unmapping
	// it goes out, and Envoy has not acknowledged it yet.
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com")}
	h.reconcile(t)
	// The counts read zero, and the ACK arrives while they are being read.
	h.duringStats = h.out.ack
	h.reconcile(t)
	h.duringStats = nil
	if !contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("the chain went on counts that may predate the ACK")
	}
	// The fake bumps the version on every Set; Envoy accepts that one too.
	// The next run reads the counts after the ACK: now it may go.
	h.out.ack()
	h.reconcile(t)
	if contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("acknowledged before the counts were read, and idle: the chain goes")
	}
}

func TestAWarmingListenerHoldsTheSweep(t *testing.T) {
	h := newHarness(t, 8)
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com", "api.openai.com")}
	h.reconcile(t)
	h.out.ack()
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com")}
	h.reconcile(t)
	h.out.ack()
	h.warming = 1 // acknowledged, but Envoy has not put it in force
	h.reconcile(t)
	h.out.ack()
	if !contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("nothing goes while a listener update is warming")
	}
	h.warming = 0
	h.reconcile(t)
	if contains(h.out.chains(), "decrypt/api.openai.com") {
		t.Fatal("settled, acknowledged and idle: the chain goes")
	}
}

// Finding: a node controller that restarts while Envoy keeps running must
// publish the chains Envoy already holds, so the streams on them survive.
func TestARestartKeepsTheChainsEnvoyHolds(t *testing.T) {
	h := newHarness(t, 8)
	h.c.Set.Apply(hostset.Wanted{}) // a fresh process: nothing learned yet
	h.active["myres.openai.azure.com"] = 1
	h.active["gone.example.com"] = 1
	h.c.Installed = func(context.Context) ([]string, error) {
		return []string{"decrypt/api.anthropic.com", "decrypt/myres.openai.azure.com", "decrypt/gone.example.com", "passthrough"}, nil
	}
	pod := podOf("a", "10.0.0.1", "api.anthropic.com")
	pod.Patterns = []string{"*.openai.azure.com"}
	h.view.snap.Pods = []nodeview.Pod{pod}
	h.reconcile(t)
	for _, want := range []string{"decrypt/api.anthropic.com", "decrypt/myres.openai.azure.com", "decrypt/gone.example.com"} {
		if !contains(h.out.chains(), want) {
			t.Fatalf("the first listener after a restart lacks %s: %v", want, h.out.chains())
		}
	}
	// The learned name is still decrypted for the pod whose pattern covers it;
	// the name nobody wants is mapped to no pod.
	if got := h.out.mapped("10.0.0.1"); strings.Join(got, ",") != "api.anthropic.com,myres.openai.azure.com" {
		t.Fatalf("pod a is decrypted for %v", got)
	}
	// It leaves through the normal retirement once idle.
	h.out.ack()
	h.active["gone.example.com"] = 0
	h.reconcile(t)
	h.out.ack()
	h.reconcile(t)
	if contains(h.out.chains(), "decrypt/gone.example.com") {
		t.Fatal("an idle adopted chain goes after the sweep")
	}
}

func TestNothingIsPublishedUntilEnvoysChainsAreKnown(t *testing.T) {
	h := newHarness(t, 8)
	h.view.snap.Pods = []nodeview.Pod{podOf("a", "10.0.0.1", "api.anthropic.com")}
	down := errors.New("admin socket not there yet")
	h.c.Installed = func(context.Context) ([]string, error) { return nil, down }
	h.reconcile(t)
	if h.out.sets != 0 {
		t.Fatal("a listener published blind could drop chains Envoy holds")
	}
	h.c.Installed = func(context.Context) ([]string, error) { return nil, nil }
	h.reconcile(t)
	if h.out.sets != 1 {
		t.Fatal("once Envoy answers, the listener is published")
	}
	// Adoption happens once.
	h.c.Installed = func(context.Context) ([]string, error) { return nil, down }
	h.reconcile(t)
	if h.out.sets != 2 {
		t.Fatal("after adoption, Envoy's admin is not needed to publish")
	}
}
