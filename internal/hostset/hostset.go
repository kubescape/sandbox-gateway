// Package hostset keeps the set of hostnames the gateway decrypts on one node.
//
// Policy objects give two lists: exact hosts and host patterns. An exact host
// is in the set as soon as an object on the node asks for it. A pattern never
// goes to Envoy as a pattern: a hostname that matches one joins the set only
// after node-agent has seen it in a workload's DNS answers. The SNI a client
// sends is never enough. One cap covers every name in the set, so a pod
// resolving many made-up names under a pattern, or a policy listing many
// hosts, cannot grow it without bound.
//
// Envoy gets one filter chain per name with its own certificate, and leaves
// are minted only for names in the set.
package hostset

import (
	"errors"
	"strings"
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

// Match reports whether host matches one policy host pattern, in the syntax
// described above. An invalid pattern matches nothing.
func Match(pattern, host string) bool {
	pt, err := parsePattern(pattern)
	if err != nil {
		return false
	}
	return pt.match(normalize(host))
}
