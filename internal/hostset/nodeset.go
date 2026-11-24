package hostset

import (
	"container/list"
	"sort"
	"strings"
	"sync"
)

// Wanted is what the policy objects on a node ask for: the union of their
// exact hosts and of their host patterns.
type Wanted struct {
	Exact    []string
	Patterns []string
}

// Counts is the node's host set measured against its cap.
type Counts struct {
	Exact   int // exact hosts in the set
	Learned int // names learned through a pattern
	Cap     int
	// OverCap is the number of names wanted now and left out because the cap
	// was reached. Their traffic passes through undecrypted.
	OverCap int
	// Evictions counts learned names removed to make room.
	Evictions int64
}

// overCapMemory bounds how many refused learned names are remembered for
// Counts.OverCap. Exact hosts over the cap are always counted.
const overCapMemory = 1024

type kind uint8

const (
	kindExact kind = iota
	kindLearned
)

// NodeSet is the set of names the gateway mints a certificate and a filter
// chain for on one node. The cap covers every name in it, exact and learned
// together, so the number of minted names holds whatever the policies say.
//
// Exact hosts come first: a new one takes a free slot, then the slot of the
// least recently seen learned name that has no open connections.
//
// A name never leaves in one step, because removing a chain cuts the streams
// on it. A name nobody wants any more, or one evicted to make room, is first
// retired: it keeps its chain and its slot, and NamesFor stops returning it,
// so no new connection is decrypted for it. Sweep removes a retired name once
// it is idle. The caller sweeps only after Envoy has taken the listener that
// no longer maps any pod to the name; from then on its connection count can
// only fall.
//
// NodeSet is safe for concurrent use. The busy callback runs with the set
// locked and must not call back into it.
type NodeSet struct {
	mu       sync.Mutex
	cap      int
	busy     func(name string) bool
	exact    map[string]bool
	lru      *list.List // learned names, front = most recently seen
	learned  map[string]*list.Element
	retired  map[string]retiree
	patterns []pattern
	rejected []string            // patterns and exact entries refused, sorted
	overE    int                 // wanted exact hosts left out
	overL    map[string]struct{} // sighted names waiting for a slot
	evicted  int64
}

// retiree is a name on its way out.
type retiree struct {
	kind kind
	// evicted: retired to make room. Such a name is not taken back when it
	// is sighted again; it waits for a slot like any newcomer.
	evicted bool
}

// NewNodeSet builds an empty set. cap <= 0 means 256. busy reports whether a
// name has open connections; nil means no name ever has.
func NewNodeSet(cap int, busy func(name string) bool) *NodeSet {
	if cap <= 0 {
		cap = 256
	}
	if busy == nil {
		busy = func(string) bool { return false }
	}
	return &NodeSet{
		cap: cap, busy: busy,
		exact: map[string]bool{}, lru: list.New(), learned: map[string]*list.Element{},
		retired: map[string]retiree{}, overL: map[string]struct{}{},
	}
}

func (s *NodeSet) size() int { return len(s.exact) + len(s.learned) + len(s.retired) }

// Apply replaces what the node's policy objects want. It reports whether the
// set of names changed.
//
// Every pattern goes through the width rule first. A pattern that fails
// learns nothing and is listed by RejectedPatterns.
func (s *NodeSet) Apply(w Wanted) (changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rejected := map[string]bool{}
	var patterns []pattern
	seenPattern := map[string]bool{}
	for _, raw := range w.Patterns {
		if seenPattern[raw] {
			continue
		}
		seenPattern[raw] = true
		if CheckWidth(raw) != nil {
			rejected[raw] = true
			continue
		}
		pt, err := parsePattern(raw)
		if err != nil {
			rejected[raw] = true
			continue
		}
		patterns = append(patterns, pt)
	}
	want := map[string]bool{}
	for _, raw := range w.Exact {
		h := normalize(raw)
		if strings.Contains(h, "*") || !validHostname(h) || !strings.Contains(h, ".") {
			rejected[raw] = true
			continue
		}
		want[h] = true
	}
	s.patterns = patterns
	s.rejected = s.rejected[:0]
	for r := range rejected {
		s.rejected = append(s.rejected, r)
	}
	sort.Strings(s.rejected)

	// Retired names that are wanted again stay where they are, as members.
	for name, r := range s.retired {
		switch {
		case want[name]:
			delete(s.retired, name)
			s.exact[name] = true
		case !r.evicted && r.kind == kindLearned && s.matches(name):
			delete(s.retired, name)
			s.learned[name] = s.lru.PushFront(name)
		}
	}
	// Exact hosts nobody wants any more.
	for name := range s.exact {
		if want[name] {
			continue
		}
		delete(s.exact, name)
		if s.matches(name) {
			s.learned[name] = s.lru.PushFront(name)
		} else {
			s.retired[name] = retiree{kind: kindExact}
		}
	}
	// Learned names whose pattern is gone, or that are now exact.
	for name, el := range s.learned {
		switch {
		case want[name]:
			s.lru.Remove(el)
			delete(s.learned, name)
			s.exact[name] = true
		case !s.matches(name):
			s.lru.Remove(el)
			delete(s.learned, name)
			s.retired[name] = retiree{kind: kindLearned}
		}
	}
	// New exact hosts, in name order so the outcome does not depend on map order.
	var add []string
	for name := range want {
		if !s.exact[name] {
			add = append(add, name)
		}
	}
	sort.Strings(add)
	s.overE = 0
	for _, name := range add {
		if s.size() >= s.cap {
			s.overE++
			continue
		}
		s.exact[name] = true
		changed = true
	}
	// Sighted names that were waiting, with the slots exact hosts left.
	for name := range s.overL {
		if !s.matches(name) {
			delete(s.overL, name)
		}
	}
	var waiting []string
	for name := range s.overL {
		waiting = append(waiting, name)
	}
	sort.Strings(waiting)
	for _, name := range waiting {
		if s.size() >= s.cap {
			break
		}
		if _, leaving := s.retired[name]; leaving {
			continue
		}
		delete(s.overL, name)
		s.learned[name] = s.lru.PushFront(name)
		changed = true
	}
	// Whoever is still left out needs a slot: start idle learned names on
	// their way out, one for each.
	s.makeRoom(s.overE + len(s.overL))
	return changed
}

// matches reports whether a valid pattern on the node covers name. The
// caller holds the lock.
func (s *NodeSet) matches(name string) bool {
	for _, pt := range s.patterns {
		if pt.match(name) {
			return true
		}
	}
	return false
}

// makeRoom retires idle learned names, least recently seen first, until as
// many slots are on their way to being free as there are names left out.
// Exact hosts are never evicted. The caller holds the lock.
func (s *NodeSet) makeRoom(leftOut int) {
	leaving := 0
	for _, r := range s.retired {
		if r.evicted {
			leaving++
		}
	}
	for el := s.lru.Back(); el != nil && leaving < leftOut; {
		prev := el.Prev()
		name := el.Value.(string)
		if !s.busy(name) {
			s.lru.Remove(el)
			delete(s.learned, name)
			s.retired[name] = retiree{kind: kindLearned, evicted: true}
			s.evicted++
			leaving++
		}
		el = prev
	}
}

// Observe records a hostname from a workload's DNS answers. It reports
// whether the set changed. A name joins only when a valid pattern on the
// node covers it. When the set is full the name waits: the next Apply retires
// an idle learned name for it, and it joins at an Apply after that name has
// been swept. When every learned name is busy it keeps waiting, and counts
// as over the cap for as long as it does.
//
// Observe itself never retires a name. It can be called at any moment, and
// the busy callback is only as fresh as the caller's last reading.
func (s *NodeSet) Observe(name string) (changed bool) {
	name = normalize(name)
	if !validHostname(name) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exact[name] {
		return false
	}
	if el, ok := s.learned[name]; ok {
		s.lru.MoveToFront(el)
		return false
	}
	if !s.matches(name) {
		return false
	}
	if r, ok := s.retired[name]; ok && !r.evicted {
		delete(s.retired, name)
		s.learned[name] = s.lru.PushFront(name)
		return false
	}
	if _, leaving := s.retired[name]; leaving || s.size() >= s.cap {
		// The name waits. Room is made for it at the next Apply and not here:
		// which name is idle has to be judged on connection counts read just
		// before, and a sighting can arrive seconds after the last reading.
		if len(s.overL) < overCapMemory {
			s.overL[name] = struct{}{}
		}
		return false
	}
	delete(s.overL, name)
	s.learned[name] = s.lru.PushFront(name)
	return true
}

// Sweep removes retired names that are idle and reports whether any went.
// Call it only once Envoy has taken a listener built after those names were
// retired; a slot it frees is filled by the next Apply.
func (s *NodeSet) Sweep() (changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.retired {
		if !s.busy(name) {
			delete(s.retired, name)
			changed = true
		}
	}
	return changed
}

// Contains reports whether name has a certificate and a chain now. Leaves
// are minted only for names this returns true for.
func (s *NodeSet) Contains(name string) bool {
	name = normalize(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exact[name] {
		return true
	}
	if _, ok := s.learned[name]; ok {
		return true
	}
	_, ok := s.retired[name]
	return ok
}

// Names returns every name in the set, sorted, retired names included.
func (s *NodeSet) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, s.size())
	for n := range s.exact {
		out = append(out, n)
	}
	for n := range s.learned {
		out = append(out, n)
	}
	for n := range s.retired {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// NamesFor returns the names one pod is decrypted for: the exact hosts of
// its own policy objects that are in the set, plus the learned names one of
// its own patterns covers, minus its passthrough entries. A passthrough entry
// with '*' is a pattern; any other is an exact name.
//
// The set is node-wide, this list is per pod: a pod is never decrypted for a
// name only another pod's policy asks for.
func (s *NodeSet) NamesFor(exact, patterns, passthrough []string) []string {
	var own []pattern
	for _, raw := range patterns {
		if CheckWidth(raw) != nil {
			continue
		}
		if pt, err := parsePattern(raw); err == nil {
			own = append(own, pt)
		}
	}
	skip := func(name string) bool {
		for _, p := range passthrough {
			if strings.Contains(p, "*") {
				if Match(p, name) {
					return true
				}
			} else if normalize(p) == name {
				return true
			}
		}
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, raw := range exact {
		h := normalize(raw)
		if s.exact[h] && !seen[h] && !skip(h) {
			seen[h] = true
			out = append(out, h)
		}
	}
	for name := range s.learned {
		if seen[name] || skip(name) {
			continue
		}
		for _, pt := range own {
			if pt.match(name) {
				seen[name] = true
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Counts returns the set's size against the cap. A retired name still holds
// its slot and counts under the kind it had.
func (s *NodeSet) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Counts{Exact: len(s.exact), Learned: len(s.learned), Cap: s.cap, OverCap: s.overE + len(s.overL), Evictions: s.evicted}
	for _, r := range s.retired {
		if r.kind == kindExact {
			c.Exact++
		} else {
			c.Learned++
		}
	}
	return c
}

// RejectedPatterns lists the entries the last Apply refused: patterns that
// fail the width rule or do not parse, and exact hosts that are not plain
// hostnames. Sorted.
func (s *NodeSet) RejectedPatterns() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.rejected...)
}
