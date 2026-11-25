package nodeview

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func pod(ns, name, node, ip string, labels map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"namespace": ns, "name": name, "labels": labels},
		"spec":     map[string]any{"nodeName": node},
		"status":   map[string]any{"phase": "Running"},
	}}
	if ip != "" {
		_ = unstructured.SetNestedSlice(u.Object, []any{map[string]any{"ip": ip}}, "status", "podIPs")
	}
	return u
}

func namespace(name string, labels map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": name, "labels": labels},
	}}
}

type decrypt struct{ exact, patterns, passthrough []any }

func (d decrypt) section() map[string]any {
	dec := map[string]any{}
	if d.exact != nil {
		dec["exactHosts"] = d.exact
	}
	if d.patterns != nil {
		dec["hostPatterns"] = d.patterns
	}
	if d.passthrough != nil {
		dec["passthrough"] = d.passthrough
	}
	return map[string]any{"default": map[string]any{"llm": "allow", "mcp": "allow", "other": "allow"}, "decrypt": dec}
}

func nsPolicy(ns, name string, match map[string]any, mode string, d *decrypt) *unstructured.Unstructured {
	spec := map[string]any{
		"selector": map[string]any{"podSelector": map[string]any{"matchLabels": match}},
		"mode":     mode, "containers": []any{"*"},
	}
	if d != nil {
		spec["http"] = d.section()
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kubescape.io/v1alpha1", "kind": "SandboxPolicy",
		"metadata": map[string]any{"namespace": ns, "name": name}, "spec": spec,
	}}
}

func clusterPolicy(name string, podMatch, nsMatch map[string]any, d decrypt) *unstructured.Unstructured {
	sel := map[string]any{"podSelector": map[string]any{"matchLabels": podMatch}}
	if nsMatch != nil {
		sel["namespaceSelector"] = map[string]any{"matchLabels": nsMatch}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kubescape.io/v1alpha1", "kind": "ClusterSandboxPolicy",
		"metadata": map[string]any{"name": name},
		"spec":     map[string]any{"selector": sel, "mode": "enforce", "containers": []any{"*"}, "http": d.section()},
	}}
}

func us(objs ...*unstructured.Unstructured) []*unstructured.Unstructured { return objs }

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestTwoPodsWithDifferentPoliciesGetDifferentLists(t *testing.T) {
	snap := build("node-a",
		us(pod("team", "a", "node-a", "10.0.0.1", map[string]any{"app": "a"}),
			pod("team", "b", "node-a", "10.0.0.2", map[string]any{"app": "b"}),
			pod("team", "plain", "node-a", "10.0.0.3", map[string]any{"app": "none"})),
		us(namespace("team", nil)),
		us(nsPolicy("team", "pa", map[string]any{"app": "a"}, "enforce", &decrypt{exact: []any{"api.anthropic.com"}, passthrough: []any{"api.openai.com"}}),
			nsPolicy("team", "pb", map[string]any{"app": "b"}, "audit", &decrypt{exact: []any{"api.openai.com"}, patterns: []any{"*.openai.azure.com"}})))
	want := []Pod{
		{Namespace: "team", Name: "a", Addrs: addrs("10.0.0.1"), Exact: []string{"api.anthropic.com"}, Passthrough: []string{"api.openai.com"}},
		{Namespace: "team", Name: "b", Addrs: addrs("10.0.0.2"), Exact: []string{"api.openai.com"}, Patterns: []string{"*.openai.azure.com"}},
	}
	if !reflect.DeepEqual(snap.Pods, want) {
		t.Fatalf("pods = %+v\nwant   %+v", snap.Pods, want)
	}
	// Every pod on the node is an on-node source, selected or not.
	if !reflect.DeepEqual(snap.OnNode, addrs("10.0.0.1", "10.0.0.2", "10.0.0.3")) {
		t.Fatalf("on node = %v", snap.OnNode)
	}
	w := snap.Wanted()
	if !reflect.DeepEqual(w.Exact, []string{"api.anthropic.com", "api.openai.com"}) || !reflect.DeepEqual(w.Patterns, []string{"*.openai.azure.com"}) {
		t.Fatalf("wanted = %+v", w)
	}
}

func TestObjectsMergePerPod(t *testing.T) {
	snap := build("node-a",
		us(pod("team", "a", "node-a", "10.0.0.1", map[string]any{"app": "a", "tier": "x"})),
		us(namespace("team", map[string]any{"env": "prod"})),
		us(nsPolicy("team", "one", map[string]any{"app": "a"}, "enforce", &decrypt{exact: []any{"api.anthropic.com", "api.openai.com"}}),
			clusterPolicy("two", map[string]any{"tier": "x"}, map[string]any{"env": "prod"}, decrypt{exact: []any{"api.openai.com"}, passthrough: []any{"api.anthropic.com"}})))
	if len(snap.Pods) != 1 {
		t.Fatalf("pods = %+v", snap.Pods)
	}
	p := snap.Pods[0]
	if !reflect.DeepEqual(p.Exact, []string{"api.anthropic.com", "api.openai.com"}) || !reflect.DeepEqual(p.Passthrough, []string{"api.anthropic.com"}) {
		t.Fatalf("pod = %+v", p)
	}
}

func TestWhatAppliesToNothing(t *testing.T) {
	d := &decrypt{exact: []any{"api.anthropic.com"}}
	on := map[string]any{"app": "a"}
	cases := []struct {
		name     string
		pods     []*unstructured.Unstructured
		spaces   []*unstructured.Unstructured
		policies []*unstructured.Unstructured
	}{
		{"mode off", us(pod("team", "a", "node-a", "10.0.0.1", on)), us(namespace("team", nil)),
			us(nsPolicy("team", "p", on, "off", d))},
		{"no http section", us(pod("team", "a", "node-a", "10.0.0.1", on)), us(namespace("team", nil)),
			us(nsPolicy("team", "p", on, "enforce", nil))},
		{"policy in another namespace", us(pod("team", "a", "node-a", "10.0.0.1", on)), us(namespace("team", nil)),
			us(nsPolicy("other", "p", on, "enforce", d))},
		{"labels do not match", us(pod("team", "a", "node-a", "10.0.0.1", map[string]any{"app": "z"})), us(namespace("team", nil)),
			us(nsPolicy("team", "p", on, "enforce", d))},
		{"cluster policy, namespace labels do not match", us(pod("team", "a", "node-a", "10.0.0.1", on)), us(namespace("team", map[string]any{"env": "dev"})),
			us(clusterPolicy("p", on, map[string]any{"env": "prod"}, *d))},
		{"cluster policy without a namespace selector", us(pod("team", "a", "node-a", "10.0.0.1", on)), us(namespace("team", nil)),
			us(clusterPolicy("p", on, nil, *d))},
		{"cluster policy, namespace not seen yet", us(pod("team", "a", "node-a", "10.0.0.1", on)), nil,
			us(clusterPolicy("p", on, map[string]any{}, *d))},
	}
	for _, c := range cases {
		if snap := build("node-a", c.pods, c.spaces, c.policies); len(snap.Pods) != 0 {
			t.Errorf("%s: pods = %+v, want none", c.name, snap.Pods)
		}
	}
	// The empty namespace selector matches every namespace that is known.
	snap := build("node-a", us(pod("team", "a", "node-a", "10.0.0.1", on)), us(namespace("team", nil)),
		us(clusterPolicy("p", on, map[string]any{}, *d)))
	if len(snap.Pods) != 1 {
		t.Fatalf("an empty namespace selector should match: %+v", snap)
	}
}

func TestPodsLeftOut(t *testing.T) {
	on := map[string]any{"app": "a"}
	hostNet := pod("team", "hostnet", "node-a", "192.168.1.10", on)
	_ = unstructured.SetNestedField(hostNet.Object, true, "spec", "hostNetwork")
	done := pod("team", "done", "node-a", "10.0.0.9", on)
	_ = unstructured.SetNestedField(done.Object, "Succeeded", "status", "phase")
	snap := build("node-a",
		us(pod("team", "elsewhere", "node-b", "10.0.1.1", on), pod("team", "pending", "node-a", "", on), hostNet, done,
			pod("team", "ok", "node-a", "10.0.0.1", on)),
		us(namespace("team", nil)),
		us(nsPolicy("team", "p", on, "enforce", &decrypt{exact: []any{"api.anthropic.com"}})))
	if len(snap.Pods) != 1 || snap.Pods[0].Name != "ok" {
		t.Fatalf("pods = %+v, want only ok", snap.Pods)
	}
	if !reflect.DeepEqual(snap.OnNode, addrs("10.0.0.1")) {
		t.Fatalf("on node = %v: another node's pod, a finished pod and a host-network pod are not on-node sources", snap.OnNode)
	}
}

func TestDualStackPodKeepsBothAddresses(t *testing.T) {
	p := pod("team", "a", "node-a", "", map[string]any{"app": "a"})
	_ = unstructured.SetNestedSlice(p.Object, []any{map[string]any{"ip": "fd00::5"}, map[string]any{"ip": "10.0.0.5"}}, "status", "podIPs")
	snap := build("node-a", us(p), us(namespace("team", nil)),
		us(nsPolicy("team", "p", map[string]any{"app": "a"}, "enforce", &decrypt{exact: []any{"api.anthropic.com"}})))
	if len(snap.Pods) != 1 || !reflect.DeepEqual(snap.Pods[0].Addrs, addrs("10.0.0.5", "fd00::5")) {
		t.Fatalf("pods = %+v", snap.Pods)
	}
}

func fakeClient(objs ...runtime.Object) *fake.FakeDynamicClient {
	return fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		Pods: "PodList", Namespaces: "NamespaceList",
		SandboxPolicies: "SandboxPolicyList", ClusterSandboxPolicies: "ClusterSandboxPolicyList",
	}, objs...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestInformersFollowTheCluster(t *testing.T) {
	on := map[string]any{"app": "a"}
	client := fakeClient(
		pod("team", "a", "node-a", "10.0.0.1", on),
		pod("team", "elsewhere", "node-b", "10.0.1.1", on), // the fake ignores the field selector
		namespace("team", nil),
	)
	src := NewInformers(client, "node-a")
	if src.Synced() {
		t.Fatal("not synced before Run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)
	waitFor(t, "sync", src.Synced)
	if snap := src.Snapshot(); len(snap.Pods) != 0 || !reflect.DeepEqual(snap.OnNode, addrs("10.0.0.1")) {
		t.Fatalf("before any policy: %+v", snap)
	}
	// Drain the notifications of the initial list.
	select {
	case <-src.Changed():
	default:
	}

	p := nsPolicy("team", "p", on, "enforce", &decrypt{exact: []any{"api.anthropic.com"}})
	if _, err := client.Resource(SandboxPolicies).Namespace("team").Create(ctx, p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-src.Changed():
	case <-time.After(5 * time.Second):
		t.Fatal("no change signalled after a policy was created")
	}
	waitFor(t, "the policy to apply", func() bool { return len(src.Snapshot().Pods) == 1 })
	if got := src.Snapshot().Pods[0]; got.Name != "a" || !reflect.DeepEqual(got.Exact, []string{"api.anthropic.com"}) {
		t.Fatalf("pod = %+v", got)
	}

	if err := client.Resource(Pods).Namespace("team").Delete(ctx, "a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pod to go", func() bool { s := src.Snapshot(); return len(s.Pods) == 0 && len(s.OnNode) == 0 })
}

func TestStaticReadsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.yaml")
	doc := `
apiVersion: v1
kind: Namespace
metadata: {name: it}
---
apiVersion: v1
kind: Pod
metadata: {namespace: it, name: it-pod, labels: {app: agent}}
spec: {nodeName: n1}
status: {phase: Running, podIPs: [{ip: 172.30.0.21}]}
---
apiVersion: kubescape.io/v1alpha1
kind: SandboxPolicy
metadata: {namespace: it, name: it}
spec:
  selector: {podSelector: {}}
  containers: ["*"]
  mode: enforce
  http:
    default: {llm: allow, mcp: allow, other: allow}
    decrypt: {exactHosts: [api.anthropic.com]}
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadStatic(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Synced() {
		t.Fatal("a static source is synced")
	}
	snap := s.Snapshot()
	if len(snap.Pods) != 1 || snap.Pods[0].Name != "it-pod" || !reflect.DeepEqual(snap.Pods[0].Exact, []string{"api.anthropic.com"}) {
		t.Fatalf("snapshot = %+v", snap)
	}
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Secret\nmetadata: {name: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStatic(path, ""); err == nil {
		t.Fatal("a kind the view does not read is an error")
	}
}
