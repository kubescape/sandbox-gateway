// Package policysource is the processor's view of the policy objects
// (contract C11). It watches SandboxPolicy and ClusterSandboxPolicy with its
// own informers and hands the evaluator the http section of each object that
// covers a workload, unmerged, by the UIDs node-agent's lookup names.
//
// The pod's fail posture never comes from here: the section that is missing
// can be the one that says deny. It comes from the bindings map.
package policysource

import (
	"context"
	"sync"
	"time"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"

	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// The two kinds the processor watches.
var (
	SandboxPolicies        = v1alpha1.SchemeGroupVersion.WithResource("sandboxpolicies")
	ClusterSandboxPolicies = v1alpha1.SchemeGroupVersion.WithResource("clustersandboxpolicies")
)

// cached is one policy object as the processor keeps it.
type cached struct {
	ref  plugin.PolicyRef
	mode string
	http v1alpha1.HTTPSection
}

// convert reads the parts of a policy object the processor uses.
func convert(u *unstructured.Unstructured) (cached, bool) {
	var obj struct {
		Spec struct {
			Mode string                `json:"mode"`
			HTTP *v1alpha1.HTTPSection `json:"http,omitempty"`
		} `json:"spec"`
	}
	if u.GetUID() == "" || runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &obj) != nil {
		return cached{}, false
	}
	c := cached{ref: plugin.PolicyRef{UID: string(u.GetUID()), Generation: u.GetGeneration()}, mode: obj.Spec.Mode}
	if obj.Spec.HTTP != nil {
		c.http = *obj.Spec.HTTP
	}
	return c, true
}

// resolveWith resolves refs against get. A UID cached at another generation
// yields the cached copy, under its own generation, and counts as outdated; a
// UID get does not find counts as missing. Each section is a deep copy, so
// one evaluation cannot change what another sees.
func resolveWith(get func(uid string) (cached, bool), refs []plugin.PolicyRef) (sections []plugin.PolicySection, outdated, missing int) {
	for _, r := range refs {
		c, ok := get(r.UID)
		if !ok {
			missing++
			continue
		}
		if c.ref.Generation != r.Generation {
			outdated++
		}
		sections = append(sections, plugin.PolicySection{Ref: c.ref, Mode: c.mode, HTTP: *c.http.DeepCopy()})
	}
	return sections, outdated, missing
}

// byUID is the informers' index of objects by UID. The informer keeps it in
// step with its store, so an object replaced under the same name leaves no
// entry for its old UID.
const byUID = "uid"

func uidIndex(obj any) ([]string, error) {
	if u, ok := obj.(*unstructured.Unstructured); ok && u.GetUID() != "" {
		return []string{string(u.GetUID())}, nil
	}
	return nil, nil
}

// Source watches both kinds through an API server.
type Source struct {
	client dynamic.Interface
	now    func() time.Time
	kinds  []*kind

	// memo keeps the converted form of each object by UID, valid while the
	// object's resourceVersion is the same.
	memoMu sync.Mutex
	memo   map[string]memoEntry
}

type memoEntry struct {
	resourceVersion string
	c               cached
}

// memoMax bounds memo; past it, it starts over.
const memoMax = 4096

// kind is one informer and its outage clock.
type kind struct {
	gvr       schema.GroupVersionResource
	informer  cache.SharedIndexInformer
	handler   cache.ResourceEventHandlerRegistration
	mu        sync.Mutex
	lostSince time.Time
}

// New returns a source that watches both kinds through client. Call Run to
// start it.
func New(client dynamic.Interface, now func() time.Time) *Source {
	s := &Source{client: client, now: now, memo: map[string]memoEntry{}}
	for _, gvr := range []schema.GroupVersionResource{SandboxPolicies, ClusterSandboxPolicies} {
		s.kinds = append(s.kinds, s.newKind(gvr))
	}
	return s
}

func (s *Source) newKind(gvr schema.GroupVersionResource) *kind {
	k := &kind{gvr: gvr}
	res := s.client.Resource(gvr)
	// Every list and watch call is counted where it happens: a failure starts
	// this kind's outage clock, a success ends it. client-go retries failed
	// calls on its own, and not every failure reaches the watch error handler.
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
			list, err := res.Namespace(metav1.NamespaceAll).List(ctx, o)
			s.observe(k, err)
			return list, err
		},
		WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			w, err := res.Namespace(metav1.NamespaceAll).Watch(ctx, o)
			s.observe(k, err)
			return w, err
		},
	}
	// The wrapper turns the streamed initial list (WatchList) off for a client
	// that does not support it, such as the fake in tests; against an API
	// server it stays on.
	k.informer = cache.NewSharedIndexInformer(cache.ToListWatcherWithWatchListSemantics(lw, s.client),
		&unstructured.Unstructured{}, 0, cache.Indexers{byUID: uidIndex})
	// A watch that breaks after it was established fails here, not in a call.
	_ = k.informer.SetWatchErrorHandlerWithContext(func(_ context.Context, _ *cache.Reflector, _ error) {
		s.lost(k)
	})
	// Any event means the watch delivers.
	k.handler, _ = k.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { s.recovered(k) },
		UpdateFunc: func(_, _ any) { s.recovered(k) },
		DeleteFunc: func(any) { s.recovered(k) },
	})
	return k
}

// Run starts the informers and returns when ctx ends.
func (s *Source) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, k := range s.kinds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k.informer.RunWithContext(ctx)
		}()
	}
	wg.Wait()
}

// Synced reports whether both informers have listed their kind once and
// delivered that list to their handlers.
func (s *Source) Synced() bool {
	for _, k := range s.kinds {
		if !k.informer.HasSynced() || k.handler == nil || !k.handler.HasSynced() {
			return false
		}
	}
	return true
}

// LostSince is the start of the oldest outage that has not ended, across
// both informers. It is zero while both are connected.
func (s *Source) LostSince() time.Time {
	var out time.Time
	for _, k := range s.kinds {
		k.mu.Lock()
		l := k.lostSince
		k.mu.Unlock()
		if !l.IsZero() && (out.IsZero() || l.Before(out)) {
			out = l
		}
	}
	return out
}

// Resolve returns the http section of each referenced object the cache holds.
// A reference whose UID is cached at another generation yields the cached copy
// and counts as outdated. A UID that is absent counts as missing.
func (s *Source) Resolve(refs []plugin.PolicyRef) (sections []plugin.PolicySection, outdated, missing int) {
	return resolveWith(s.get, refs)
}

// get finds the object with uid in either informer's store.
func (s *Source) get(uid string) (cached, bool) {
	for _, k := range s.kinds {
		objs, err := k.informer.GetIndexer().ByIndex(byUID, uid)
		if err != nil || len(objs) == 0 {
			continue
		}
		u, ok := objs[0].(*unstructured.Unstructured)
		if !ok {
			continue
		}
		rv := u.GetResourceVersion()
		s.memoMu.Lock()
		m, hit := s.memo[uid]
		s.memoMu.Unlock()
		if hit && m.resourceVersion == rv {
			return m.c, true
		}
		c, ok := convert(u)
		if !ok {
			return cached{}, false
		}
		s.memoMu.Lock()
		if len(s.memo) >= memoMax {
			s.memo = map[string]memoEntry{}
		}
		s.memo[uid] = memoEntry{resourceVersion: rv, c: c}
		s.memoMu.Unlock()
		return c, true
	}
	return cached{}, false
}

// observe counts one list or watch call of kind.
func (s *Source) observe(k *kind, err error) {
	if err != nil {
		s.lost(k)
		return
	}
	s.recovered(k)
}

// lost starts kind's outage clock, unless it is already running.
func (s *Source) lost(k *kind) {
	k.mu.Lock()
	if k.lostSince.IsZero() {
		k.lostSince = s.now()
	}
	k.mu.Unlock()
}

// recovered ends kind's outage. Only kind's own activity calls it: one
// informer recovering says nothing about the other.
func (s *Source) recovered(k *kind) {
	k.mu.Lock()
	k.lostSince = time.Time{}
	k.mu.Unlock()
}
