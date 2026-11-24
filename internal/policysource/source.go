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

// index holds the cached objects by UID. It is safe for concurrent use.
type index struct {
	mu    sync.RWMutex
	byUID map[string]cached
}

func newIndex() *index { return &index{byUID: map[string]cached{}} }

// put converts and stores one object. An object that does not convert is
// dropped from the index, so a stale copy does not linger under its UID.
func (ix *index) put(u *unstructured.Unstructured) {
	var obj struct {
		Spec struct {
			Mode string                `json:"mode"`
			HTTP *v1alpha1.HTTPSection `json:"http,omitempty"`
		} `json:"spec"`
	}
	uid := string(u.GetUID())
	if uid == "" {
		return
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &obj); err != nil {
		delete(ix.byUID, uid)
		return
	}
	c := cached{ref: plugin.PolicyRef{UID: uid, Generation: u.GetGeneration()}, mode: obj.Spec.Mode}
	if obj.Spec.HTTP != nil {
		c.http = *obj.Spec.HTTP
	}
	ix.byUID[uid] = c
}

func (ix *index) remove(uid string) {
	ix.mu.Lock()
	delete(ix.byUID, uid)
	ix.mu.Unlock()
}

// resolve returns the cached section of each reference. A UID cached at
// another generation yields the cached copy, under its own generation, and
// counts as outdated; a UID that is absent counts as missing.
func (ix *index) resolve(refs []plugin.PolicyRef) (sections []plugin.PolicySection, outdated, missing int) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	for _, r := range refs {
		c, ok := ix.byUID[r.UID]
		if !ok {
			missing++
			continue
		}
		if c.ref.Generation != r.Generation {
			outdated++
		}
		sections = append(sections, plugin.PolicySection{Ref: c.ref, Mode: c.mode, HTTP: c.http})
	}
	return sections, outdated, missing
}

// Source watches both kinds through an API server.
type Source struct {
	client dynamic.Interface
	now    func() time.Time
	ix     *index
	kinds  []*kind
}

// kind is one informer and its outage clock.
type kind struct {
	gvr       schema.GroupVersionResource
	informer  cache.SharedIndexInformer
	mu        sync.Mutex
	lostSince time.Time
}

// New returns a source that watches both kinds through client. Call Run to
// start it.
func New(client dynamic.Interface, now func() time.Time) *Source {
	s := &Source{client: client, now: now, ix: newIndex()}
	for _, gvr := range []schema.GroupVersionResource{SandboxPolicies, ClusterSandboxPolicies} {
		s.kinds = append(s.kinds, s.newKind(gvr))
	}
	return s
}

func (s *Source) newKind(gvr schema.GroupVersionResource) *kind {
	k := &kind{gvr: gvr}
	res := s.client.Resource(gvr)
	// A successful list or watch call means the API server answers again, so
	// each clears this kind's outage clock. So does any event (see the
	// handlers below).
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
			list, err := res.Namespace(metav1.NamespaceAll).List(ctx, o)
			if err == nil {
				s.recovered(k)
			}
			return list, err
		},
		WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			w, err := res.Namespace(metav1.NamespaceAll).Watch(ctx, o)
			if err == nil {
				s.recovered(k)
			}
			return w, err
		},
	}
	// The wrapper turns the streamed initial list (WatchList) off for a client
	// that does not support it, such as the fake in tests; against an API
	// server it stays on.
	k.informer = cache.NewSharedIndexInformer(cache.ToListWatcherWithWatchListSemantics(lw, s.client),
		&unstructured.Unstructured{}, 0, cache.Indexers{})
	_ = k.informer.SetWatchErrorHandlerWithContext(func(_ context.Context, _ *cache.Reflector, _ error) {
		s.lost(k)
	})
	_, _ = k.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { s.upsert(k, obj) },
		UpdateFunc: func(_, obj any) { s.upsert(k, obj) },
		DeleteFunc: func(obj any) { s.delete(k, obj) },
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

// Synced reports whether both informers have listed their kind once.
func (s *Source) Synced() bool {
	for _, k := range s.kinds {
		if !k.informer.HasSynced() {
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
	return s.ix.resolve(refs)
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

func (s *Source) upsert(k *kind, obj any) {
	s.recovered(k)
	if u, ok := obj.(*unstructured.Unstructured); ok {
		s.ix.put(u)
	}
}

func (s *Source) delete(k *kind, obj any) {
	s.recovered(k)
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
	if u, ok := obj.(*unstructured.Unstructured); ok {
		s.ix.remove(string(u.GetUID()))
	}
}
