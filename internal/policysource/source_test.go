package policysource

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubescape/sandbox-gateway/internal/stale"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)} }

// policy builds one object of either kind. host goes into decrypt.exactHosts.
func policy(cluster bool, name, uid string, generation int64, mode, host string) *unstructured.Unstructured {
	kind := "SandboxPolicy"
	if cluster {
		kind = "ClusterSandboxPolicy"
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kubescape.io/v1alpha1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"mode": mode,
			"http": map[string]any{
				"default": map[string]any{"llm": "allow", "mcp": "allow", "other": "allow"},
				"decrypt": map[string]any{"exactHosts": []any{host}},
			},
		},
	}}
	if !cluster {
		u.SetNamespace("agents")
	}
	u.SetUID(types.UID(uid))
	u.SetGeneration(generation)
	return u
}

func newClient(objs ...runtime.Object) *fake.FakeDynamicClient {
	return fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		SandboxPolicies:        "SandboxPolicyList",
		ClusterSandboxPolicies: "ClusterSandboxPolicyList",
	}, objs...)
}

// start runs a source until the test ends and waits for it to sync.
func start(t *testing.T, client *fake.FakeDynamicClient, clk *clock) *Source {
	t.Helper()
	s := New(client, clk.now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, s.Synced, "the first sync")
	return s
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestResolveExactlyNamedObjects(t *testing.T) {
	s := start(t, newClient(
		policy(false, "a", "uid-a", 1, "enforce", "a.example.com"),
		policy(false, "b", "uid-b", 2, "audit", "b.example.com"),
		policy(false, "c", "uid-c", 3, "enforce", "c.example.com"),
	), newClock())
	sections, outdated, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-a", Generation: 1}, {UID: "uid-b", Generation: 2}})
	if outdated != 0 || missing != 0 || len(sections) != 2 {
		t.Fatalf("sections=%d outdated=%d missing=%d", len(sections), outdated, missing)
	}
	for i, want := range []struct{ uid, mode, host string }{{"uid-a", "enforce", "a.example.com"}, {"uid-b", "audit", "b.example.com"}} {
		sec := sections[i]
		if sec.Ref.UID != want.uid || sec.Mode != want.mode || sec.HTTP.Decrypt == nil || sec.HTTP.Decrypt.ExactHosts[0] != want.host {
			t.Fatalf("section %d = %+v", i, sec)
		}
	}
}

func TestOutdatedGeneration(t *testing.T) {
	s := start(t, newClient(policy(false, "a", "uid-a", 4, "enforce", "a.example.com")), newClock())
	sections, outdated, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-a", Generation: 5}})
	if outdated != 1 || missing != 0 || len(sections) != 1 || sections[0].Ref.Generation != 4 {
		t.Fatalf("sections=%+v outdated=%d missing=%d", sections, outdated, missing)
	}
}

func TestMissingUID(t *testing.T) {
	s := start(t, newClient(policy(false, "a", "uid-a", 1, "enforce", "a.example.com")), newClock())
	sections, outdated, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-a", Generation: 1}, {UID: "uid-gone", Generation: 1}})
	if missing != 1 || outdated != 0 || len(sections) != 1 {
		t.Fatalf("sections=%d outdated=%d missing=%d", len(sections), outdated, missing)
	}
}

func TestClusterAndNamespacedKinds(t *testing.T) {
	s := start(t, newClient(
		policy(false, "ns", "uid-ns", 1, "enforce", "ns.example.com"),
		policy(true, "cl", "uid-cl", 1, "enforce", "cl.example.com"),
	), newClock())
	if sections, _, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-ns", Generation: 1}, {UID: "uid-cl", Generation: 1}}); missing != 0 || len(sections) != 2 {
		t.Fatalf("sections=%d missing=%d", len(sections), missing)
	}
}

func TestObjectWithoutHTTPSection(t *testing.T) {
	u := policy(false, "a", "uid-a", 1, "enforce", "x")
	unstructured.RemoveNestedField(u.Object, "spec", "http")
	s := start(t, newClient(u), newClock())
	sections, _, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-a", Generation: 1}})
	if missing != 0 || len(sections) != 1 || sections[0].HTTP.Decrypt != nil || len(sections[0].HTTP.Rules) != 0 {
		t.Fatalf("sections = %+v", sections)
	}
}

// failLists makes list calls for one resource fail while down is set.
func failLists(client *fake.FakeDynamicClient, resource string, down *atomic.Bool) {
	client.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		if down.Load() {
			return true, nil, errors.New("api server unreachable")
		}
		return false, nil, nil
	})
}

func TestNotSyncedBeforeFirstList(t *testing.T) {
	client := newClient(policy(false, "a", "uid-a", 1, "enforce", "a.example.com"))
	var down atomic.Bool
	down.Store(true)
	failLists(client, "sandboxpolicies", &down)
	clk := newClock()
	s := New(client, clk.now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, func() bool { return !s.LostSince().IsZero() }, "the failed list to start the outage clock")
	if s.Synced() {
		t.Fatal("synced while the list fails")
	}
	down.Store(false)
	waitFor(t, s.Synced, "the sync once the list works")
}

func TestLostSinceSetAndCleared(t *testing.T) {
	client := newClient()
	var down atomic.Bool
	down.Store(true)
	failLists(client, "clustersandboxpolicies", &down)
	clk := newClock()
	s := New(client, clk.now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, func() bool { return !s.LostSince().IsZero() }, "the outage clock")
	if got := s.LostSince(); !got.Equal(clk.now()) {
		t.Fatalf("LostSince = %v, want %v", got, clk.now())
	}
	down.Store(false)
	waitFor(t, func() bool { return s.LostSince().IsZero() }, "the outage to end")
}

// Review: activity on one informer must not end the other's outage.
func TestOneInformerRecoveringLeavesOtherLost(t *testing.T) {
	clk := newClock()
	s := New(newClient(), clk.now)
	ns, cl := s.kinds[0], s.kinds[1]
	first := clk.now()
	s.lost(ns)
	clk.set(first.Add(time.Minute))
	s.lost(cl)
	// Events arrive on the cluster informer only.
	clk.set(first.Add(2 * time.Minute))
	s.recovered(cl)
	if got := s.LostSince(); !got.Equal(first) {
		t.Fatalf("LostSince = %v, want the namespaced outage's start %v", got, first)
	}
	tr := stale.New(5*time.Minute, clk.now)
	clk.set(first.Add(5 * time.Minute))
	if !tr.Observe(1, time.Time{}, s.LostSince(), false) {
		t.Fatal("not degraded five minutes into the namespaced informer's outage")
	}
	s.recovered(ns)
	if !s.LostSince().IsZero() {
		t.Fatal("LostSince not cleared once both recovered")
	}
}

func TestLoadStatic(t *testing.T) {
	path := t.TempDir() + "/policies.yaml"
	doc := `apiVersion: kubescape.io/v1alpha1
kind: SandboxPolicy
metadata: {name: a, namespace: it, uid: uid-a, generation: 2}
spec:
  mode: enforce
  http:
    default: {llm: allow, mcp: allow, other: allow}
    decrypt: {exactHosts: [api.anthropic.com]}
---
apiVersion: kubescape.io/v1alpha1
kind: ClusterSandboxPolicy
metadata: {name: b, uid: uid-b, generation: 1}
spec: {mode: audit}
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	sections, outdated, missing := s.Resolve(s.Refs())
	if len(sections) != 2 || outdated+missing != 0 || sections[0].HTTP.Decrypt.ExactHosts[0] != "api.anthropic.com" || sections[1].Mode != "audit" {
		t.Fatalf("sections = %+v", sections)
	}
	if !s.Synced() || !s.LostSince().IsZero() {
		t.Fatal("a static source is synced and never lost")
	}
}

// Review: an object replaced under the same name (deleted and created again,
// so with a new UID) must not stay resolvable under its old UID.
func TestReplacedObjectRetiresOldUID(t *testing.T) {
	client := newClient(policy(false, "a", "uid-old", 1, "enforce", "a.example.com"))
	s := start(t, client, newClock())
	res := client.Resource(SandboxPolicies).Namespace("agents")
	ctx := context.Background()
	if err := res.Delete(ctx, "a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := res.Create(ctx, policy(false, "a", "uid-new", 1, "enforce", "a.example.com"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, _, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-new", Generation: 1}})
		return missing == 0
	}, "the new object")
	if _, _, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-old", Generation: 1}}); missing != 1 {
		t.Fatal("the replaced object still resolves under its old UID")
	}
}

// Review: the same replacement delivered as one update event, the way a
// watch that missed the delete reports it.
func TestReplacedObjectInOneUpdateRetiresOldUID(t *testing.T) {
	client := newClient(policy(false, "a", "uid-old", 1, "enforce", "a.example.com"))
	s := start(t, client, newClock())
	res := client.Resource(SandboxPolicies).Namespace("agents")
	if _, err := res.Update(context.Background(), policy(false, "a", "uid-new", 1, "enforce", "a.example.com"), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, _, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-new", Generation: 1}})
		return missing == 0
	}, "the new object")
	if _, _, missing := s.Resolve([]plugin.PolicyRef{{UID: "uid-old", Generation: 1}}); missing != 1 {
		t.Fatal("the replaced object still resolves under its old UID")
	}
}

// Review: errors client-go retries inside the reflector, without calling the
// watch error handler, still start the outage clock.
func TestRetryableWatchErrorCountsAsLost(t *testing.T) {
	for name, werr := range map[string]error{
		"too many requests":  apierrors.NewTooManyRequests("slow down", 1),
		"connection refused": &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
	} {
		t.Run(name, func(t *testing.T) {
			client := newClient()
			var down atomic.Bool
			down.Store(true)
			client.PrependWatchReactor("clustersandboxpolicies", func(k8stesting.Action) (bool, watch.Interface, error) {
				if down.Load() {
					return true, nil, werr
				}
				return false, nil, nil
			})
			s := New(client, newClock().now)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go s.Run(ctx)
			waitFor(t, func() bool { return !s.LostSince().IsZero() }, "a retried watch error to start the outage clock")
			down.Store(false)
			waitFor(t, func() bool { return s.LostSince().IsZero() }, "a successful watch call to end it")
		})
	}
}

// Review: a failed watch call starts the outage clock where it happens, even
// when client-go retries it without reporting it.
func TestFailedWatchCallCountsAsLost(t *testing.T) {
	client := newClient()
	var down atomic.Bool
	client.PrependWatchReactor("clustersandboxpolicies", func(k8stesting.Action) (bool, watch.Interface, error) {
		if down.Load() {
			return true, nil, errors.New("api server unreachable")
		}
		return false, nil, nil
	})
	clk := newClock()
	down.Store(true) // the list works, every watch call fails
	s := New(client, clk.now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, func() bool { return !s.LostSince().IsZero() }, "a failed watch call to start the outage clock")
	down.Store(false)
	waitFor(t, func() bool { return s.LostSince().IsZero() }, "a successful watch call to end it")
}

// Review: each evaluation gets its own copy of the sections.
func TestSectionsAreCopies(t *testing.T) {
	s := start(t, newClient(policy(false, "a", "uid-a", 1, "enforce", "a.example.com")), newClock())
	refs := []plugin.PolicyRef{{UID: "uid-a", Generation: 1}}
	first, _, _ := s.Resolve(refs)
	first[0].HTTP.Decrypt.ExactHosts[0] = "changed.example.com"
	second, _, _ := s.Resolve(refs)
	if second[0].HTTP.Decrypt.ExactHosts[0] != "a.example.com" {
		t.Fatal("a change to one resolve's sections showed up in the next")
	}
}
