package extproc

import (
	"net"
	"strings"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/hostset"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// Framework rules from the decision table.
const (
	// RuleNoCachedPolicy blocks a deny pod none of whose covering policies is
	// in the cache: there is nothing to evaluate it against.
	RuleNoCachedPolicy = "framework.no-cached-policy"
	// RuleHostNotDecrypted blocks a request to a host no covering policy
	// decrypts: the gateway decrypted traffic it should have passed through.
	RuleHostNotDecrypted = "framework.host-not-decrypted"
)

// input is what the decision table looks at for one request.
type input struct {
	HasEvaluator      bool
	Posture           string // from the bindings table
	Sections          int    // covering policies found in the cache
	Unresolved        int    // references missing from the cache or at another generation
	Stale             bool   // the staleness tracker's answer
	HostInDecryptList bool
	Verdict           plugin.Verdict // zero before Evaluate
}

// outcome is the table's answer.
type outcome struct {
	Block, Degraded, CallEvaluate bool
	Rule                          string
}

// decide is the decision table of the processor plan (PR 5), first match
// wins. Called before Evaluate with a zero verdict, it says whether to call
// Evaluate at all; called again with the verdict, whether to block. The fail
// posture comes from the bindings table, never from the sections.
func decide(in input) outcome {
	deny := in.Posture == conntable.PostureDeny
	switch {
	case in.Sections == 0 && in.HasEvaluator && deny:
		return outcome{Block: true, Degraded: true, Rule: RuleNoCachedPolicy}
	case in.Sections == 0:
		return outcome{Degraded: true}
	case !in.HostInDecryptList && (!in.Stale || deny):
		return outcome{Block: true, Degraded: in.Stale, Rule: RuleHostNotDecrypted}
	case !in.HostInDecryptList:
		return outcome{Degraded: true}
	case !in.HasEvaluator:
		return outcome{Degraded: in.Stale}
	}
	v := in.Verdict
	if v.Action == plugin.ActionDeny && v.Mode == plugin.ModeEnforce {
		switch {
		case !in.Stale:
			return outcome{CallEvaluate: true, Block: true, Rule: v.Rule}
		case deny:
			return outcome{CallEvaluate: true, Block: true, Degraded: true, Rule: v.Rule}
		default: // degraded on an allow pod: recorded as would-deny
			return outcome{CallEvaluate: true, Degraded: true, Rule: v.Rule}
		}
	}
	return outcome{CallEvaluate: true, Degraded: in.Stale, Rule: v.Rule}
}

// inDecryptList reports whether host is in the decrypt list of the cached
// sections: the union of their exact hosts and the names their host patterns
// match, minus their passthrough hosts.
func inDecryptList(sections []plugin.PolicySection, host string) bool {
	host = normalizeHost(host)
	in := false
	for _, s := range sections {
		d := s.HTTP.Decrypt
		if d == nil {
			continue
		}
		for _, p := range d.Passthrough {
			if matchHost(p, host) {
				return false
			}
		}
		for _, h := range d.ExactHosts {
			in = in || normalizeHost(h) == host
		}
		for _, p := range d.HostPatterns {
			in = in || hostset.Match(p, host)
		}
	}
	return in
}

// matchHost matches a passthrough entry, which can be a name or a pattern.
func matchHost(entry, host string) bool {
	if strings.Contains(entry, "*") {
		return hostset.Match(entry, host)
	}
	return normalizeHost(entry) == host
}

// normalizeHost drops a port and a trailing dot, and lowers the case.
func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}
