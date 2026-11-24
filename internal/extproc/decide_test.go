package extproc

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"

	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

var (
	enforceDenyV = plugin.Verdict{Action: plugin.ActionDeny, Mode: plugin.ModeEnforce, Rule: "r"}
	auditDenyV   = plugin.Verdict{Action: plugin.ActionDeny, Mode: plugin.ModeAudit, Rule: "r"}
	allowV       = plugin.Verdict{Action: plugin.ActionAllow, Mode: plugin.ModeEnforce, Rule: "r"}
)

// One row per line of the plan's table, in its order.
func TestDecisionTable(t *testing.T) {
	ok := input{HasEvaluator: true, Posture: "allow", Sections: 1, HostInDecryptList: true}
	with := func(f func(*input)) input { in := ok; f(&in); return in }
	for _, c := range []struct {
		name string
		in   input
		want outcome
	}{
		{"nothing cached, evaluator, deny pod", with(func(i *input) { i.Sections, i.Posture = 0, "deny" }),
			outcome{Block: true, Degraded: true, Rule: RuleNoCachedPolicy}},
		{"nothing cached, allow pod", with(func(i *input) { i.Sections = 0 }), outcome{Degraded: true}},
		{"nothing cached, no evaluator, deny pod", with(func(i *input) { i.Sections, i.HasEvaluator, i.Posture = 0, false, "deny" }),
			outcome{Degraded: true}},
		{"host not decrypted, fresh", with(func(i *input) { i.HostInDecryptList = false }),
			outcome{Block: true, Rule: RuleHostNotDecrypted}},
		{"host not decrypted, stale, deny pod", with(func(i *input) { i.HostInDecryptList, i.Stale, i.Posture = false, true, "deny" }),
			outcome{Block: true, Degraded: true, Rule: RuleHostNotDecrypted}},
		{"host not decrypted, stale, allow pod", with(func(i *input) { i.HostInDecryptList, i.Stale = false, true }),
			outcome{Degraded: true}},
		{"host not decrypted, no evaluator", with(func(i *input) { i.HostInDecryptList, i.HasEvaluator = false, false }),
			outcome{Block: true, Rule: RuleHostNotDecrypted}},
		{"no evaluator", with(func(i *input) { i.HasEvaluator = false }), outcome{}},
		{"no evaluator, stale", with(func(i *input) { i.HasEvaluator, i.Stale = false, true }), outcome{Degraded: true}},
		{"enforce deny, fresh", with(func(i *input) { i.Verdict = enforceDenyV }),
			outcome{CallEvaluate: true, Block: true, Rule: "r"}},
		{"enforce deny, stale, deny pod", with(func(i *input) { i.Verdict, i.Stale, i.Posture = enforceDenyV, true, "deny" }),
			outcome{CallEvaluate: true, Block: true, Degraded: true, Rule: "r"}},
		{"enforce deny, stale, allow pod", with(func(i *input) { i.Verdict, i.Stale = enforceDenyV, true }),
			outcome{CallEvaluate: true, Degraded: true, Rule: "r"}},
		{"audit deny", with(func(i *input) { i.Verdict = auditDenyV }), outcome{CallEvaluate: true, Rule: "r"}},
		{"allow, stale", with(func(i *input) { i.Verdict, i.Stale = allowV, true }), outcome{CallEvaluate: true, Degraded: true, Rule: "r"}},
		{"before Evaluate", ok, outcome{CallEvaluate: true}},
	} {
		if got := decide(c.in); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// The posture comes from the bindings table. The sections' onUnavailable is
// not an input to the table at all, so it cannot decide.
func TestPostureFromBindingNotSections(t *testing.T) {
	stale := input{HasEvaluator: true, Sections: 1, HostInDecryptList: true, Stale: true, Verdict: enforceDenyV}
	stale.Posture = "allow" // sections may say onUnavailable: deny
	if decide(stale).Block {
		t.Fatal("allow pod blocked on a degraded decision")
	}
	stale.Posture = "deny" // sections may say onUnavailable: allow
	if !decide(stale).Block {
		t.Fatal("deny pod passed on a degraded decision")
	}
}

func TestNoEvaluatorDenyPodNothingCachedPasses(t *testing.T) {
	if o := decide(input{Posture: "deny"}); o.Block || !o.Degraded || o.CallEvaluate {
		t.Fatalf("%+v", o)
	}
}

// One of two references missing: decided from the one that resolves, and
// not degraded until the tracker says so.
func TestOneMissingReferenceOfTwoNotDegradedAtOnce(t *testing.T) {
	o := decide(input{HasEvaluator: true, Posture: "deny", Sections: 1, Unresolved: 1, HostInDecryptList: true})
	if o.Degraded || o.Block || !o.CallEvaluate {
		t.Fatalf("%+v", o)
	}
}

func TestInDecryptList(t *testing.T) {
	sec := func(d v1alpha1.HTTPDecrypt) plugin.PolicySection {
		return plugin.PolicySection{HTTP: v1alpha1.HTTPSection{Decrypt: &d}}
	}
	sections := []plugin.PolicySection{
		sec(v1alpha1.HTTPDecrypt{ExactHosts: []string{"api.anthropic.com"}}),
		sec(v1alpha1.HTTPDecrypt{HostPatterns: []string{"bedrock-runtime.*.amazonaws.com"}, Passthrough: []string{"bedrock-runtime.eu-west-1.amazonaws.com"}}),
		{}, // no http section
	}
	for host, want := range map[string]bool{
		"api.anthropic.com":                       true,
		"API.Anthropic.com:443":                   true,
		"bedrock-runtime.us-east-1.amazonaws.com": true,
		"bedrock-runtime.eu-west-1.amazonaws.com": false, // passthrough wins
		"api.openai.com":                          false,
	} {
		if got := inDecryptList(sections, host); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
}
