package extproc

import (
	"sync"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"

	"github.com/kubescape/sandbox-gateway/internal/lookup"
	"github.com/kubescape/sandbox-gateway/internal/stale"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// fakePolicies is a policy source over a fixed set of objects.
type fakePolicies struct {
	mu        sync.Mutex
	byUID     map[string]plugin.PolicySection
	lostSince time.Time
}

func (f *fakePolicies) Resolve(refs []plugin.PolicyRef) (out []plugin.PolicySection, outdated, missing int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range refs {
		s, ok := f.byUID[r.UID]
		if !ok {
			missing++
			continue
		}
		if s.Ref.Generation != r.Generation {
			outdated++
		}
		out = append(out, s)
	}
	return out, outdated, missing
}

func (f *fakePolicies) LostSince() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lostSince
}

// section is a cached policy that decrypts api.anthropic.com.
func section(uid string, gen int64) plugin.PolicySection {
	return plugin.PolicySection{Ref: plugin.PolicyRef{UID: uid, Generation: gen}, Mode: "enforce",
		HTTP: v1alpha1.HTTPSection{OnUnavailable: v1alpha1.HTTPUnavailableDeny,
			Decrypt: &v1alpha1.HTTPDecrypt{ExactHosts: []string{"api.anthropic.com"}}}}
}

func policies(sections ...plugin.PolicySection) *fakePolicies {
	f := &fakePolicies{byUID: map[string]plugin.PolicySection{}}
	for _, s := range sections {
		f.byUID[s.Ref.UID] = s
	}
	return f
}

// workloadWith is the test workload covered by refs.
func workloadWith(refs ...lookup.PolicyRef) LookupFunc {
	w := testWorkload()
	w.Policies = refs
	return fixedLookup(w, time.Time{}, nil)
}

type tclock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *tclock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *tclock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTClock() *tclock { return &tclock{t: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)} }

// oneRequest sends a whole request and returns the answer to its last part.
func oneRequest(t *testing.T, h *harness, authority string) (resp string, blocked bool) {
	t.Helper()
	st := h.stream(t)
	r := sendHeaders(t, st, ":authority", authority)
	if r.GetImmediateResponse() != nil {
		return immediateBody(r), true
	}
	sendBody(t, st, reqBody, true)
	r = recv(t, st)
	must(t, st.CloseSend())
	if r.GetImmediateResponse() != nil {
		return immediateBody(r), true
	}
	return forwarded(r), false
}

func TestSectionsOfExactlyTheNamedObjects(t *testing.T) {
	f := allowAll()
	_, h := start(t, Config{Evaluator: f,
		Policies: policies(section("uid-a", 1), section("uid-b", 1), section("uid-c", 1)),
		Lookup:   workloadWith(lookup.PolicyRef{UID: "uid-a", Generation: 1}, lookup.PolicyRef{UID: "uid-c", Generation: 1})})
	if _, blocked := oneRequest(t, h, "api.anthropic.com"); blocked {
		t.Fatal("blocked")
	}
	r := f.lastRequest()
	if len(r.Sections) != 2 || r.Sections[0].Ref.UID != "uid-a" || r.Sections[1].Ref.UID != "uid-c" || r.Degraded {
		t.Fatalf("sections = %+v degraded=%v", r.Sections, r.Degraded)
	}
}

func TestMissingReferenceDegradesAfterFiveMinutes(t *testing.T) {
	clk := newTClock()
	f := allowAll()
	_, h := start(t, Config{Evaluator: f, Stale: stale.New(5*time.Minute, clk.now),
		Policies: policies(section("uid-a", 1)),
		Lookup:   workloadWith(lookup.PolicyRef{UID: "uid-a", Generation: 1}, lookup.PolicyRef{UID: "uid-gone", Generation: 1})})
	oneRequest(t, h, "api.anthropic.com")
	if r := f.lastRequest(); r.Degraded || len(r.Sections) != 1 {
		t.Fatalf("first request: degraded=%v sections=%d", r.Degraded, len(r.Sections))
	}
	clk.advance(5 * time.Minute)
	oneRequest(t, h, "api.anthropic.com")
	if !f.lastRequest().Degraded {
		t.Fatal("not degraded five minutes after the first miss")
	}
	if recs := h.waitRecords(t, 2); recs[0].Degraded || !recs[1].Degraded {
		t.Fatalf("records degraded = %v, %v", recs[0].Degraded, recs[1].Degraded)
	}
	if n := h.srv.DegradedDecisions(); n != 1 {
		t.Fatalf("degraded decisions = %d", n)
	}
}

// staleServer is a server whose informers lost the API server an hour ago.
func staleServer(t *testing.T, f *fakeEval, posture string) *harness {
	t.Helper()
	tb := newTable()
	if posture == "allow" {
		tb = allowPodTable()
	}
	p := policies(section("uid-a", 4))
	p.lostSince = time.Now().Add(-time.Hour)
	_, h := start(t, Config{Evaluator: f, Conns: tb, Policies: p})
	return h
}

func TestDegradedDoesNotBlockAllowPod(t *testing.T) {
	h := staleServer(t, enforceDeny(), "allow")
	if _, blocked := oneRequest(t, h, "api.anthropic.com"); blocked {
		t.Fatal("degraded enforce deny blocked an allow pod")
	}
	if rec := h.waitRecords(t, 1)[0]; !rec.Degraded || !rec.WouldDeny || rec.Ended == "denied" {
		t.Fatalf("record: %+v", rec)
	}
}

func TestDegradedStillBlocksDenyPod(t *testing.T) {
	h := staleServer(t, enforceDeny(), "deny")
	if body, blocked := oneRequest(t, h, "api.anthropic.com"); !blocked || body != fakeDenyBody(fakeRuleID) {
		t.Fatalf("blocked=%v body=%s", blocked, body)
	}
	if rec := h.waitRecords(t, 1)[0]; !rec.Degraded || rec.Ended != "denied" {
		t.Fatalf("record: %+v", rec)
	}
}

func TestDenyPodNothingCachedBlocked(t *testing.T) {
	f := allowAll()
	_, h := start(t, Config{Evaluator: f, Policies: policies()}) // the lookup names uid-a; nothing cached
	// Review: refused at the headers, before any of the body is forwarded.
	st := h.stream(t)
	r := sendHeaders(t, st)
	if !is403(r) || immediateBody(r) != frameworkBody {
		t.Fatalf("headers answer = %v", r)
	}
	if c, e, d, _ := f.counts(); c+e+d != 0 {
		t.Fatalf("the evaluator was called: classify %d, evaluate %d, deny %d", c, e, d)
	}
	must(t, st.CloseSend())
	if rec := h.waitRecords(t, 1)[0]; !rec.Degraded || rec.Verdict.Rule != RuleNoCachedPolicy || rec.RequestBytes != 0 {
		t.Fatalf("record: %+v", rec)
	}
}

func TestAllowPodNothingCachedPasses(t *testing.T) {
	f := enforceDeny()
	_, h := start(t, Config{Evaluator: f, Conns: allowPodTable(), Policies: policies()})
	if _, blocked := oneRequest(t, h, "api.anthropic.com"); blocked {
		t.Fatal("blocked")
	}
	if c, e, _, _ := f.counts(); c+e != 0 {
		t.Fatalf("the evaluator was called: classify %d, evaluate %d", c, e)
	}
	if rec := h.waitRecords(t, 1)[0]; !rec.Degraded {
		t.Fatalf("record: %+v", rec)
	}
}

// The cached section says onUnavailable: deny; the bindings table says
// allow. The bindings table decides.
func TestPostureComesFromBindings(t *testing.T) {
	h := staleServer(t, enforceDeny(), "allow")
	if _, blocked := oneRequest(t, h, "api.anthropic.com"); blocked {
		t.Fatal("the section's onUnavailable decided instead of the binding's posture")
	}
	if w := h.eval.lastRequest().Workload; w.Posture != "allow" {
		t.Fatalf("workload posture = %q", w.Posture)
	}
}

func TestHostOutsideDecryptListFails(t *testing.T) {
	f := allowAll()
	_, h := start(t, Config{Evaluator: f, Policies: policies(section("uid-a", 4))})
	if body, blocked := oneRequest(t, h, "api.openai.com"); !blocked || body != frameworkBody {
		t.Fatalf("blocked=%v body=%s", blocked, body)
	}
	if c, e, _, _ := f.counts(); c+e != 0 {
		t.Fatalf("the evaluator was called: classify %d, evaluate %d", c, e)
	}
	if rec := h.waitRecords(t, 1)[0]; rec.Verdict.Rule != RuleHostNotDecrypted || rec.Ended != "denied" {
		t.Fatalf("record: %+v", rec)
	}
	// Without an evaluator the guard still runs (decision 4).
	_, h = start(t, Config{Policies: policies(section("uid-a", 4))})
	if _, blocked := oneRequest(t, h, "api.openai.com"); !blocked {
		t.Fatal("no evaluator: the guard did not run")
	}
}
