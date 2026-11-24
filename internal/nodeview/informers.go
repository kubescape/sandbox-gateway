package nodeview

import (
	"context"
	"sync"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"
)

// The resources the view watches. The service account needs list and watch
// on each.
var (
	Pods                   = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	Namespaces             = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	SandboxPolicies        = v1alpha1.SchemeGroupVersion.WithResource("sandboxpolicies")
	ClusterSandboxPolicies = v1alpha1.SchemeGroupVersion.WithResource("clustersandboxpolicies")
)

// Informers is a Source over an API server: pods scheduled on one node,
// namespaces (for a cluster policy's namespace selector) and both policy
// kinds.
type Informers struct {
	node      string
	pods      cache.SharedIndexInformer
	spaces    cache.SharedIndexInformer
	policies  []cache.SharedIndexInformer
	handlers  []cache.ResourceEventHandlerRegistration
	changed   chan struct{}
	informers []cache.SharedIndexInformer
}

// NewInformers returns a source for the node named node. Call Run to start it.
func NewInformers(client dynamic.Interface, node string) *Informers {
	s := &Informers{node: node, changed: make(chan struct{}, 1)}
	s.pods = s.informer(client, Pods, fields.OneTermEqualSelector("spec.nodeName", node).String())
	s.spaces = s.informer(client, Namespaces, "")
	s.policies = []cache.SharedIndexInformer{
		s.informer(client, SandboxPolicies, ""),
		s.informer(client, ClusterSandboxPolicies, ""),
	}
	return s
}

func (s *Informers) informer(client dynamic.Interface, gvr schema.GroupVersionResource, fieldSelector string) cache.SharedIndexInformer {
	res := client.Resource(gvr)
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
			o.FieldSelector = fieldSelector
			return res.Namespace(metav1.NamespaceAll).List(ctx, o)
		},
		WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			o.FieldSelector = fieldSelector
			return res.Namespace(metav1.NamespaceAll).Watch(ctx, o)
		},
	}
	// The wrapper turns the streamed initial list off for a client that does
	// not support it, such as the fake in tests.
	inf := cache.NewSharedIndexInformer(cache.ToListWatcherWithWatchListSemantics(lw, client),
		&unstructured.Unstructured{}, 0, cache.Indexers{})
	h, _ := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { s.notify() },
		UpdateFunc: func(_, _ any) { s.notify() },
		DeleteFunc: func(any) { s.notify() },
	})
	s.handlers = append(s.handlers, h)
	s.informers = append(s.informers, inf)
	return inf
}

func (s *Informers) notify() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Run starts the informers and returns when ctx ends.
func (s *Informers) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, inf := range s.informers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inf.RunWithContext(ctx)
		}()
	}
	wg.Wait()
}

// Synced reports whether every informer has listed its kind once and
// delivered that list.
func (s *Informers) Synced() bool {
	for i, inf := range s.informers {
		if !inf.HasSynced() || s.handlers[i] == nil || !s.handlers[i].HasSynced() {
			return false
		}
	}
	return true
}

// Changed implements Source.
func (s *Informers) Changed() <-chan struct{} { return s.changed }

// Snapshot implements Source.
func (s *Informers) Snapshot() Snapshot {
	var policies []*unstructured.Unstructured
	for _, inf := range s.policies {
		policies = append(policies, list(inf)...)
	}
	return build(s.node, list(s.pods), list(s.spaces), policies)
}

func list(inf cache.SharedIndexInformer) []*unstructured.Unstructured {
	objs := inf.GetStore().List()
	out := make([]*unstructured.Unstructured, 0, len(objs))
	for _, o := range objs {
		if u, ok := o.(*unstructured.Unstructured); ok {
			out = append(out, u)
		}
	}
	return out
}
