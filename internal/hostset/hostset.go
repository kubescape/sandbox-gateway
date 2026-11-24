// Package hostset keeps the set of hostnames the gateway decrypts on one node
// (decision #5, 2026-11-10).
//
// The compiled policy gives two lists: exact hosts and host patterns. Exact
// hosts are always in the set. A pattern never goes to Envoy as a pattern:
// a hostname that matches one joins the set only after the node agent has seen
// it in a workload's DNS answers (Observe). The SNI a client sends is never
// enough. Learned names are capped per node, least recently seen evicted first,
// so a pod resolving many made-up names under a pattern can't grow the set
// without bound.
//
// The output (Hosts) is a plain list of exact names: Envoy gets one filter
// chain per name with a prefetched certificate, and the SDS server mints only
// for names in the set. Envoy never opens an SDS subscription for a name that
// isn't in the set, which is what locked nodes out in the SNI flood (AC5).
package hostset

import (
	"container/list"
	"errors"
	"sort"
	"strings"
	"sync"
)

// Pattern syntax, as the policy catalog writes it:
//
//	*.example.com                one or more labels before example.com (not example.com itself)
//	bedrock-runtime.*.amazonaws.com   '*' inside a label matches within that label only
//	*-aiplatform.googleapis.com       same, as a label prefix
type pattern struct {
	raw       string
	anyPrefix bool     // leading "*." : one or more whole labels
	labels    []string // remaining labels; '*' matches within one label
}

func parsePattern(p string) (pattern, error) {
	p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
	if p == "" || p == "*" {
		return pattern{}, errors.New("empty or match-all pattern")
	}
	pt := pattern{raw: p}
	if strings.HasPrefix(p, "*.") {
		pt.anyPrefix = true
		p = p[2:]
	}
	pt.labels = strings.Split(p, ".")
	if len(pt.labels) < 2 {
		return pattern{}, errors.New("pattern needs at least a registrable domain: " + pt.raw)
	}
	for _, l := range pt.labels {
		if l == "" {
			return pattern{}, errors.New("empty label in pattern: " + pt.raw)
		}
	}
	// The last two labels must be literal so a pattern can't span a whole TLD.
	for _, l := range pt.labels[len(pt.labels)-2:] {
		if strings.Contains(l, "*") {
			return pattern{}, errors.New("wildcard in the registrable domain: " + pt.raw)
		}
	}
	return pt, nil
}

func (pt pattern) match(host string) bool {
	hl := strings.Split(host, ".")
	n := len(pt.labels)
	if pt.anyPrefix {
		if len(hl) <= n {
			return false
		}
		hl = hl[len(hl)-n:]
	} else if len(hl) != n {
		return false
	}
	for i, l := range pt.labels {
		if !globLabel(l, hl[i]) {
			return false
		}
	}
	return true
}

// globLabel matches one DNS label against a pattern label where '*' matches any
// run of characters (never a dot: labels are already split).
func globLabel(p, s string) bool {
	if !strings.Contains(p, "*") {
		return p == s
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, part := range parts[1:] {
		last := i == len(parts)-2
		if last {
			return strings.HasSuffix(s, part) && len(s) >= len(part)
		}
		j := strings.Index(s, part)
		if j < 0 {
			return false
		}
		s = s[j+len(part):]
	}
	return true
}

// Set is safe for concurrent use.
type Set struct {
	mu       sync.Mutex
	exact    map[string]bool
	patterns []pattern
	cap      int
	lru      *list.List // front = most recently seen; values are hostnames
	learned  map[string]*list.Element
	evicted  int // learned names dropped by the cap
}

// New builds a set. capLearned bounds the names learned through patterns; it
// does not limit exact hosts. capLearned <= 0 means 64.
func New(exact, patterns []string, capLearned int) (*Set, error) {
	if capLearned <= 0 {
		capLearned = 64
	}
	s := &Set{exact: map[string]bool{}, cap: capLearned, lru: list.New(), learned: map[string]*list.Element{}}
	for _, h := range exact {
		h = normalize(h)
		if h == "" || strings.Contains(h, "*") {
			return nil, errors.New("not an exact host: " + h)
		}
		s.exact[h] = true
	}
	for _, p := range patterns {
		pt, err := parsePattern(p)
		if err != nil {
			return nil, err
		}
		s.patterns = append(s.patterns, pt)
	}
	return s, nil
}

func normalize(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// validHostname reports whether name is a plain DNS hostname: letters, digits
// and hyphens in dot-separated labels. A wildcard label in a pattern matches
// any bytes, so a learned name is checked here before it joins the set that
// Envoy's listener is built from.
func validHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			switch c := l[i]; {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// Contains reports whether name is in the set now (exact or learned). The SDS
// server mints only for names this returns true for.
func (s *Set) Contains(name string) bool {
	name = normalize(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exact[name] {
		return true
	}
	_, ok := s.learned[name]
	return ok
}

// Observe records a hostname from a workload's DNS answers. It returns true when
// the set changed (a new name joined, possibly evicting the oldest one), so the
// caller knows to rebuild Envoy's listener. A name already learned is refreshed;
// a name that matches no pattern, or is already exact, is ignored.
func (s *Set) Observe(name string) (changed bool) {
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
	matched := false
	for _, pt := range s.patterns {
		if pt.match(name) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	s.learned[name] = s.lru.PushFront(name)
	for s.lru.Len() > s.cap {
		old := s.lru.Back()
		s.lru.Remove(old)
		delete(s.learned, old.Value.(string))
		s.evicted++
	}
	return true
}

// Hosts returns every name in the set, sorted: exact hosts and learned names.
func (s *Set) Hosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.exact)+len(s.learned))
	for h := range s.exact {
		out = append(out, h)
	}
	for h := range s.learned {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Learned returns the number of names learned through patterns.
func (s *Set) Learned() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lru.Len()
}

// Evicted returns how many learned names the cap has dropped.
func (s *Set) Evicted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evicted
}

// Match reports whether host matches one policy host pattern, in the syntax
// described above. An invalid pattern matches nothing.
func Match(pattern, host string) bool {
	pt, err := parsePattern(pattern)
	if err != nil {
		return false
	}
	return pt.match(normalize(host))
}
