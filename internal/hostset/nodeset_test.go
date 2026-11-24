package hostset

import (
	"fmt"
	"reflect"
	"testing"
)

type busySet map[string]bool

func (b busySet) is(name string) bool { return b[name] }

func exactHosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("h%03d.example.com", i)
	}
	return out
}

func TestCapHoldsWithMoreExactHostsThanSlots(t *testing.T) {
	s := NewNodeSet(256, nil)
	if !s.Apply(Wanted{Exact: exactHosts(300)}) {
		t.Fatal("first Apply should change the set")
	}
	c := s.Counts()
	if c.Exact != 256 || c.Learned != 0 || c.OverCap != 44 || c.Cap != 256 {
		t.Fatalf("counts = %+v, want 256 exact and 44 over the cap", c)
	}
	if len(s.Names()) != 256 {
		t.Fatalf("%d names in the set", len(s.Names()))
	}
	if !s.Contains("h000.example.com") || s.Contains("h299.example.com") {
		t.Fatal("hosts are admitted in name order; the last ones are over the cap")
	}
	// The same input again changes nothing and keeps the same 256.
	if s.Apply(Wanted{Exact: exactHosts(300)}) {
		t.Fatal("re-applying the same input must not change the set")
	}
	// A host that sorts first does not displace one that already has a chain.
	if s.Apply(Wanted{Exact: append([]string{"a.example.com"}, exactHosts(300)...)}) {
		t.Fatal("a full set of exact hosts admits nothing new")
	}
	if s.Contains("a.example.com") || s.Counts().OverCap != 45 {
		t.Fatalf("counts = %+v", s.Counts())
	}
}

func TestExactHostTakesAnIdleLearnedSlot(t *testing.T) {
	busy := busySet{}
	s := NewNodeSet(3, busy.is)
	w := Wanted{Exact: []string{"api.anthropic.com"}, Patterns: []string{"*.openai.azure.com"}}
	s.Apply(w)
	for _, n := range []string{"a.openai.azure.com", "b.openai.azure.com"} {
		if !s.Observe(n) {
			t.Fatalf("%s should join", n)
		}
	}
	busy["a.openai.azure.com"] = true // the older one has open connections
	w.Exact = append(w.Exact, "api.openai.com")

	// Round one: the idle learned name is retired, not removed. It keeps its
	// chain, no pod is decrypted for it, and the exact host waits.
	s.Apply(w)
	if s.Contains("api.openai.com") || !s.Contains("b.openai.azure.com") {
		t.Fatalf("names = %v: nothing may leave or join in the same step", s.Names())
	}
	if got := s.NamesFor(nil, []string{"*.openai.azure.com"}, nil); !reflect.DeepEqual(got, []string{"a.openai.azure.com"}) {
		t.Fatalf("the retired name must be in no pod's list, got %v", got)
	}
	if c := s.Counts(); c.Evictions != 1 || c.OverCap != 1 {
		t.Fatalf("counts = %+v", c)
	}
	// Applying again before the sweep retires nothing more.
	s.Apply(w)
	if c := s.Counts(); c.Evictions != 1 {
		t.Fatalf("one newcomer needs one slot: %+v", c)
	}
	// Round two, after Envoy took the listener: the slot is freed and filled.
	if !s.Sweep() {
		t.Fatal("the retired name is idle")
	}
	if !s.Apply(w) {
		t.Fatal("the exact host should join now")
	}
	if !s.Contains("api.openai.com") || !s.Contains("a.openai.azure.com") || s.Contains("b.openai.azure.com") {
		t.Fatalf("names = %v: the idle learned name should have gone, not the busy one", s.Names())
	}
	if c := s.Counts(); c.Evictions != 1 || c.OverCap != 0 {
		t.Fatalf("counts = %+v", c)
	}
}

func TestFullOfBusyNamesPassesTheNewcomerThrough(t *testing.T) {
	busy := busySet{"a.openai.azure.com": true, "b.openai.azure.com": true}
	s := NewNodeSet(2, busy.is)
	w := Wanted{Patterns: []string{"*.openai.azure.com"}}
	s.Apply(w)
	s.Observe("a.openai.azure.com")
	s.Observe("b.openai.azure.com")
	if s.Observe("c.openai.azure.com") {
		t.Fatal("no idle name to evict: the sighting must not change the set")
	}
	if s.Contains("c.openai.azure.com") {
		t.Fatal("the newcomer must be left out")
	}
	if c := s.Counts(); c.OverCap != 1 || c.Evictions != 0 || c.Learned != 2 {
		t.Fatalf("counts = %+v", c)
	}
	// The same refused name is counted once.
	s.Observe("c.openai.azure.com")
	if c := s.Counts(); c.OverCap != 1 {
		t.Fatalf("counts = %+v", c)
	}
	// The sighting is posted once, so the set remembers it. When a name goes
	// idle it is retired at the next Apply, and after the sweep the waiting
	// name joins without being sighted again.
	delete(busy, "a.openai.azure.com")
	s.Apply(w)
	if c := s.Counts(); c.Evictions != 1 || s.Contains("c.openai.azure.com") {
		t.Fatalf("counts = %+v, names = %v", c, s.Names())
	}
	s.Sweep()
	if !s.Apply(w) || !s.Contains("c.openai.azure.com") || s.Contains("a.openai.azure.com") {
		t.Fatalf("names = %v", s.Names())
	}
	if c := s.Counts(); c.OverCap != 0 || c.Evictions != 1 {
		t.Fatalf("counts = %+v", c)
	}
}

func TestEvictedNameSightedAgainWaitsLikeANewcomer(t *testing.T) {
	s := NewNodeSet(1, nil)
	w := Wanted{Patterns: []string{"*.openai.azure.com"}}
	s.Apply(w)
	s.Observe("a.openai.azure.com")
	s.Observe("b.openai.azure.com") // retires a
	s.Observe("a.openai.azure.com") // a is on its way out: it waits too
	if got := s.NamesFor(nil, w.Patterns, nil); len(got) != 0 {
		t.Fatalf("a is retired and b is waiting, got %v", got)
	}
	s.Sweep()
	s.Apply(w)
	if got := s.Names(); len(got) != 1 {
		t.Fatalf("the cap is one name, got %v", got)
	}
}

func TestRejectedPatternLearnsNothing(t *testing.T) {
	s := NewNodeSet(8, nil)
	s.Apply(Wanted{Patterns: []string{"*.amazonaws.com", "*.amazonaws.com", "*.openai.azure.com", "Bad.*.example.com"}})
	if s.Observe("bedrock-runtime.us-east-1.amazonaws.com") {
		t.Fatal("a name under a rejected pattern must not be learned")
	}
	if !s.Observe("myres.openai.azure.com") {
		t.Fatal("the valid pattern still learns")
	}
	if got, want := s.RejectedPatterns(), []string{"*.amazonaws.com", "Bad.*.example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rejected = %v, want %v", got, want)
	}
	// An exact entry that is not a plain hostname is refused too.
	s.Apply(Wanted{Exact: []string{"*.example.com", "ok.example.com", "localhost"}})
	if got, want := s.RejectedPatterns(), []string{"*.example.com", "localhost"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rejected = %v, want %v", got, want)
	}
	if !s.Contains("ok.example.com") {
		t.Fatal("the valid exact host is admitted")
	}
}

func TestSNIAloneNeverJoins(t *testing.T) {
	s := NewNodeSet(8, nil)
	s.Apply(Wanted{Exact: []string{"api.anthropic.com"}})
	if s.Observe("evil.example.com") || s.Contains("evil.example.com") {
		t.Fatal("a name no pattern covers must not join")
	}
}

func TestUnwantedNameStaysWhileBusy(t *testing.T) {
	busy := busySet{"api.openai.com": true}
	s := NewNodeSet(8, busy.is)
	s.Apply(Wanted{Exact: []string{"api.anthropic.com", "api.openai.com"}})
	if s.Apply(Wanted{Exact: []string{"api.anthropic.com"}}) {
		t.Fatal("the dropped host is busy: nothing leaves yet")
	}
	if !s.Contains("api.openai.com") {
		t.Fatal("a busy name keeps its chain")
	}
	if got := s.NamesFor([]string{"api.openai.com"}, nil, nil); len(got) != 0 {
		t.Fatalf("a retired name is in no pod's list, got %v", got)
	}
	if c := s.Counts(); c.Exact != 2 {
		t.Fatalf("a retired name still holds a slot: %+v", c)
	}
	if s.Sweep() {
		t.Fatal("still busy")
	}
	delete(busy, "api.openai.com")
	if !s.Sweep() || s.Contains("api.openai.com") {
		t.Fatal("an idle retired name goes on the next sweep")
	}
	// Wanted again while retired: it is exact again without a new chain.
	busy["api.anthropic.com"] = true
	s.Apply(Wanted{})
	if s.Apply(Wanted{Exact: []string{"api.anthropic.com"}}) {
		t.Fatal("the name never left the set")
	}
	if got := s.NamesFor([]string{"api.anthropic.com"}, nil, nil); !reflect.DeepEqual(got, []string{"api.anthropic.com"}) {
		t.Fatalf("got %v", got)
	}
}

func TestLearnedNameLeavesWithItsPattern(t *testing.T) {
	s := NewNodeSet(8, nil)
	s.Apply(Wanted{Patterns: []string{"*.openai.azure.com"}})
	s.Observe("myres.openai.azure.com")
	s.Apply(Wanted{})
	if !s.Contains("myres.openai.azure.com") {
		t.Fatal("the name is retired first and keeps its chain")
	}
	if !s.Sweep() || s.Contains("myres.openai.azure.com") {
		t.Fatal("a learned name goes when no pattern covers it")
	}
}

func TestNamesForIsPerPod(t *testing.T) {
	s := NewNodeSet(8, nil)
	s.Apply(Wanted{
		Exact:    []string{"api.anthropic.com", "api.openai.com"},
		Patterns: []string{"*.openai.azure.com", "bedrock-runtime.*.amazonaws.com"},
	})
	s.Observe("myres.openai.azure.com")
	s.Observe("bedrock-runtime.us-east-1.amazonaws.com")

	a := s.NamesFor([]string{"api.anthropic.com"}, []string{"*.openai.azure.com"}, nil)
	if want := []string{"api.anthropic.com", "myres.openai.azure.com"}; !reflect.DeepEqual(a, want) {
		t.Fatalf("pod A: %v, want %v", a, want)
	}
	b := s.NamesFor([]string{"API.OpenAI.com."}, []string{"bedrock-runtime.*.amazonaws.com"}, nil)
	if want := []string{"api.openai.com", "bedrock-runtime.us-east-1.amazonaws.com"}; !reflect.DeepEqual(b, want) {
		t.Fatalf("pod B: %v, want %v", b, want)
	}
	// Passthrough removes an exact name and everything under a pattern entry.
	c := s.NamesFor([]string{"api.anthropic.com", "api.openai.com"}, []string{"*.openai.azure.com"},
		[]string{"api.openai.com", "*.openai.azure.com"})
	if want := []string{"api.anthropic.com"}; !reflect.DeepEqual(c, want) {
		t.Fatalf("pod C: %v, want %v", c, want)
	}
	// A pod's own pattern that fails the width rule gives it nothing.
	if d := s.NamesFor(nil, []string{"*.amazonaws.com"}, nil); len(d) != 0 {
		t.Fatalf("pod D: %v", d)
	}
}

func TestNameOverTheCapIsInNoPodsList(t *testing.T) {
	s := NewNodeSet(1, nil)
	s.Apply(Wanted{Exact: []string{"a.example.com", "b.example.com"}})
	if got := s.NamesFor([]string{"a.example.com", "b.example.com"}, nil, nil); !reflect.DeepEqual(got, []string{"a.example.com"}) {
		t.Fatalf("got %v", got)
	}
}

func TestObserveRejectsNonHostnames(t *testing.T) {
	s := NewNodeSet(8, nil)
	s.Apply(Wanted{Patterns: []string{"*.openai.azure.com"}})
	for _, n := range []string{"a b.openai.azure.com", "x\n.openai.azure.com", "-x.openai.azure.com", "*.openai.azure.com", "é.openai.azure.com"} {
		if s.Observe(n) || s.Contains(n) {
			t.Errorf("%q must not join the set", n)
		}
	}
}
