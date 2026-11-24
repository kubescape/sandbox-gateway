package xds

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"strings"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// stable renders a listener as indented JSON. protojson's own spacing is not
// stable between runs, so the output goes through encoding/json.
func stable(t *testing.T, l *listenerv3.Listener) []byte {
	t.Helper()
	raw, err := protojson.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	return append(buf.Bytes(), '\n')
}

func twoPods() Input {
	return Input{
		Names: []string{"api.openai.com", "api.anthropic.com", "myres.openai.azure.com"},
		Pods: []PodNames{
			{Addrs: addrs("10.0.0.2"), Names: []string{"api.openai.com", "myres.openai.azure.com"}},
			{Addrs: addrs("10.0.0.1", "fd00::1"), Names: []string{"api.anthropic.com"}},
			{Addrs: addrs("10.0.0.3")}, // selected, decrypts nothing
		},
	}
}

func TestEgressGolden(t *testing.T) {
	l, err := Config{}.Egress(twoPods())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateAll(); err != nil {
		t.Fatalf("the listener does not validate: %v", err)
	}
	got := stable(t, l)
	const path = "testdata/egress.golden.json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("listener differs from %s; run go test ./internal/xds -update and review the diff", path)
	}
}

func TestSameInputGivesAnEqualListener(t *testing.T) {
	a, err := Config{}.Egress(twoPods())
	if err != nil {
		t.Fatal(err)
	}
	// The same node, listed in another order.
	in := twoPods()
	in.Names[0], in.Names[2] = in.Names[2], in.Names[0]
	in.Pods[0], in.Pods[1] = in.Pods[1], in.Pods[0]
	b, err := Config{}.Egress(in)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(a, b) {
		t.Fatal("order of the input must not change the listener")
	}
}

func chainNames(l *listenerv3.Listener) []string {
	var out []string
	for _, fc := range l.GetFilterChains() {
		out = append(out, fc.GetName())
	}
	return out
}

func TestOneChainPerNameAndNoWildcard(t *testing.T) {
	l, err := Config{}.Egress(twoPods())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"decrypt/api.anthropic.com", "decrypt/api.openai.com", "decrypt/myres.openai.azure.com", "passthrough"}
	if got := chainNames(l); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("chains = %v, want %v", got, want)
	}
	for _, fc := range l.GetFilterChains() {
		// Pod addresses and names live in the matcher. A chain that carried
		// them would be replaced, and its streams cut, when a pod came or went.
		if fc.GetFilterChainMatch() != nil {
			t.Errorf("chain %s has a filter_chain_match", fc.GetName())
		}
	}
	if l.GetDefaultFilterChain() != nil {
		t.Error("there is no default chain: an unknown source must get none")
	}
	if _, err := (Config{}).Egress(Input{Names: []string{"*.anthropic.com"}}); err == nil {
		t.Fatal("a wildcard must never become a chain")
	}
	if _, err := (Config{}).Egress(Input{Names: []string{"a.com\nname: x"}}); err == nil {
		t.Fatal("a name that is not a hostname must be refused")
	}
}

// pick walks the matcher the way Envoy does and returns the chain name, or
// "" when nothing matches.
func pick(t *testing.T, l *listenerv3.Listener, source, sni string) string {
	t.Helper()
	tree := l.GetFilterChainMatcher().GetMatcherTree()
	on, ok := tree.GetExactMatchMap().GetMap()[source]
	if !ok {
		if l.GetFilterChainMatcher().GetOnNoMatch() != nil {
			t.Fatal("the top level must have no on_no_match")
		}
		return ""
	}
	action := on.GetAction()
	if sub := on.GetMatcher(); sub != nil {
		if hit, ok := sub.GetMatcherTree().GetExactMatchMap().GetMap()[sni]; ok {
			action = hit.GetAction()
		} else {
			action = sub.GetOnNoMatch().GetAction()
		}
	}
	// The action is a StringValue holding the chain name.
	raw := string(action.GetTypedConfig().GetValue())
	for _, n := range chainNames(l) {
		if strings.HasSuffix(raw, n) {
			return n
		}
	}
	t.Fatalf("action %q names no chain of the listener", raw)
	return ""
}

func TestAPodIsDecryptedOnlyForItsOwnNames(t *testing.T) {
	l, err := Config{}.Egress(twoPods())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ source, sni, want string }{
		{"10.0.0.1", "api.anthropic.com", "decrypt/api.anthropic.com"},
		{"fd00::1", "api.anthropic.com", "decrypt/api.anthropic.com"},
		{"10.0.0.2", "api.openai.com", "decrypt/api.openai.com"},
		{"10.0.0.2", "myres.openai.azure.com", "decrypt/myres.openai.azure.com"},
		// Another pod's policy names the host; this pod's does not.
		{"10.0.0.1", "api.openai.com", "passthrough"},
		{"10.0.0.2", "api.anthropic.com", "passthrough"},
		{"10.0.0.1", "pypi.org", "passthrough"},
		{"10.0.0.1", "", "passthrough"},
		{"10.0.0.3", "api.anthropic.com", "passthrough"},
		// Not a pod the view knows: no chain at all.
		{"10.0.0.99", "api.anthropic.com", ""},
		{"192.168.1.10", "pypi.org", ""},
	}
	for _, c := range cases {
		if got := pick(t, l, c.source, c.sni); got != c.want {
			t.Errorf("%s asking for %q: chain %q, want %q", c.source, c.sni, got, c.want)
		}
	}
}

func TestANameWithoutAChainIsNotMatched(t *testing.T) {
	// The pod wants a name the host set left out (over the cap).
	l, err := Config{}.Egress(Input{
		Names: []string{"api.anthropic.com"},
		Pods:  []PodNames{{Addrs: addrs("10.0.0.1"), Names: []string{"api.anthropic.com", "api.openai.com"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := pick(t, l, "10.0.0.1", "api.openai.com"); got != "passthrough" {
		t.Fatalf("chain %q, want passthrough", got)
	}
}

func TestPodChangesTouchOnlyTheMatcher(t *testing.T) {
	before, err := Config{}.Egress(twoPods())
	if err != nil {
		t.Fatal(err)
	}
	in := twoPods()
	in.Pods = append(in.Pods[:1], PodNames{Addrs: addrs("10.0.0.7"), Names: []string{"api.anthropic.com", "api.openai.com"}})
	after, err := Config{}.Egress(in)
	if err != nil {
		t.Fatal(err)
	}
	if proto.Equal(before.GetFilterChainMatcher(), after.GetFilterChainMatcher()) {
		t.Fatal("the matcher should have changed")
	}
	if len(before.GetFilterChains()) != len(after.GetFilterChains()) {
		t.Fatal("chains added or removed")
	}
	for i := range before.GetFilterChains() {
		if !proto.Equal(before.GetFilterChains()[i], after.GetFilterChains()[i]) {
			t.Fatalf("chain %s changed when only pods did; Envoy would drain it", before.GetFilterChains()[i].GetName())
		}
	}
	// Everything outside the chains and the matcher is listener-wide and fixed.
	strip := func(l *listenerv3.Listener) *listenerv3.Listener {
		c := proto.Clone(l).(*listenerv3.Listener)
		c.FilterChains, c.FilterChainMatcher = nil, nil
		return c
	}
	if !proto.Equal(strip(before), strip(after)) {
		t.Fatal("a listener-wide field changed")
	}
}

func TestNoPodsStillBuilds(t *testing.T) {
	l, err := Config{}.Egress(Input{})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateAll(); err != nil {
		t.Fatal(err)
	}
	if got := chainNames(l); len(got) != 1 || got[0] != "passthrough" {
		t.Fatalf("chains = %v", got)
	}
	if got := pick(t, l, "10.0.0.1", "api.anthropic.com"); got != "" {
		t.Fatalf("with no pods nothing matches, got %q", got)
	}
}

func TestSharedAddressDecryptsNeither(t *testing.T) {
	l, err := Config{}.Egress(Input{
		Names: []string{"api.anthropic.com"},
		Pods: []PodNames{
			{Addrs: addrs("10.0.0.1"), Names: []string{"api.anthropic.com"}},
			{Addrs: addrs("10.0.0.1")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := pick(t, l, "10.0.0.1", "api.anthropic.com"); got != "passthrough" {
		t.Fatalf("chain %q, want passthrough", got)
	}
}

func TestChainSettings(t *testing.T) {
	l, err := Config{}.Egress(Input{Names: []string{"api.anthropic.com"}})
	if err != nil {
		t.Fatal(err)
	}
	js := string(stable(t, l))
	// protojson leaves a false field out, so the check is that true is absent.
	if strings.Contains(js, `"failureModeAllow": true`) {
		t.Error("ext_proc must fail closed")
	}
	for _, want := range []string{
		`"requestBodyMode": "FULL_DUPLEX_STREAMED"`,
		`"responseBodyMode": "FULL_DUPLEX_STREAMED"`,
		`"disableStatelessSessionResumption": true`,
		`"disableStatefulSessionResumption": true`,
		`"useRemoteAddress": true`,
		`"skipXffAppend": true`,
		`"upgradeType": "websocket"`,
		`"alt-svc"`,
		`"key": "accept-encoding"`,
		`"value": "identity"`,
		`"statPrefix": "egress_api_anthropic_com"`,
		`"api.anthropic.com:443"`,
		`"initialFetchTimeout": "0s"`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the decrypt chain lacks %s", want)
		}
	}
	if strings.Contains(js, "proxy_protocol") {
		t.Error("the listener must not parse PROXY protocol")
	}
	if strings.Contains(js, "on_demand_secret") {
		t.Error("the chain uses a plain SDS secret")
	}
}

func TestPassthroughGoesToTheOriginalDestination(t *testing.T) {
	l, err := Config{}.Egress(Input{})
	if err != nil {
		t.Fatal(err)
	}
	// original_dst must run before the chain is picked and before any filter
	// that waits for bytes, so the address is restored for every connection.
	var filters []string
	for _, f := range l.GetListenerFilters() {
		filters = append(filters, f.GetName())
	}
	if want := "envoy.filters.listener.original_dst,envoy.filters.listener.tls_inspector"; strings.Join(filters, ",") != want {
		t.Fatalf("listener filters = %v, want %s", filters, want)
	}
	// The filter must not hand the connection to another listener.
	if l.GetUseOriginalDst().GetValue() {
		t.Fatal("use_original_dst must stay unset")
	}
	js := string(stable(t, l))
	if !strings.Contains(js, `"cluster": "orig_dst"`) {
		t.Error("the passthrough chain must forward to the original-destination cluster")
	}
	// Nothing on the passthrough path may pick a destination from the SNI.
	for _, banned := range []string{"sni_dynamic_forward_proxy", "sni_cluster", "dynamic_forward_proxy"} {
		if strings.Contains(js, banned) {
			t.Errorf("the listener with no decrypt chain contains %s", banned)
		}
	}
}
