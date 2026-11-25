// Package nodeview is the node controller's view of the cluster: the pods
// scheduled on this node and, for each, what the policy objects that select
// it ask the gateway to decrypt.
//
// The view is per pod on purpose. The host set is node-wide, but a pod is
// decrypted only for the hosts its own policy names, so every list here
// belongs to one pod.
package nodeview

import (
	"context"
	"net/netip"
	"sort"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kubescape/sandbox-gateway/internal/hostset"
)

// Pod is one pod on the node that at least one policy object with an http
// section selects.
type Pod struct {
	Namespace, Name string
	// Addrs are the pod's own addresses. Envoy sees them as the source of the
	// pod's redirected connections.
	Addrs []netip.Addr
	// The decrypt lists of every object that applies to the pod, merged:
	// exact hosts and patterns are unions, and so is passthrough, which wins
	// over both.
	Exact, Patterns, Passthrough []string
}

// Snapshot is the node at one moment. Slices are sorted, so two snapshots of
// the same state are equal.
type Snapshot struct {
	// Pods are the pods a policy object applies to.
	Pods []Pod
	// OnNode holds the address of every pod on the node, selected or not.
	// Pods on the host network are left out: they use the node's address.
	OnNode []netip.Addr
}

// Wanted is the union of what the node's pods ask for, for the host set.
func (s Snapshot) Wanted() hostset.Wanted {
	var w hostset.Wanted
	for _, p := range s.Pods {
		w.Exact = append(w.Exact, p.Exact...)
		w.Patterns = append(w.Patterns, p.Patterns...)
	}
	w.Exact, w.Patterns = uniq(w.Exact), uniq(w.Patterns)
	return w
}

// Source gives the current snapshot. Implementations are safe for
// concurrent use.
type Source interface {
	// Snapshot builds the view from what the source holds now.
	Snapshot() Snapshot
	// Synced reports whether the source has seen the cluster once. Before
	// that a snapshot is incomplete and must not replace a listener.
	Synced() bool
	// Changed receives a value after the source's objects change. Several
	// changes may arrive as one.
	Changed() <-chan struct{}
	// Run feeds the source until ctx ends.
	Run(ctx context.Context)
}

// podInfo is the part of a Pod object the view reads.
type podInfo struct {
	namespace, name string
	labels          map[string]string
	node            string
	hostNetwork     bool
	finished        bool
	addrs           []netip.Addr
}

// policy is the part of a policy object the view reads.
type policy struct {
	namespace string // empty for a cluster policy
	cluster   bool
	pods      labels.Selector
	spaces    labels.Selector // cluster policies only
	decrypt   v1alpha1.HTTPDecrypt
}

func readPod(u *unstructured.Unstructured) podInfo {
	p := podInfo{namespace: u.GetNamespace(), name: u.GetName(), labels: u.GetLabels()}
	p.node, _, _ = unstructured.NestedString(u.Object, "spec", "nodeName")
	p.hostNetwork, _, _ = unstructured.NestedBool(u.Object, "spec", "hostNetwork")
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	// A finished pod's address can already belong to another pod.
	p.finished = phase == "Succeeded" || phase == "Failed"
	ips, _, _ := unstructured.NestedSlice(u.Object, "status", "podIPs")
	for _, e := range ips {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		s, _ := m["ip"].(string)
		if a, err := netip.ParseAddr(s); err == nil {
			p.addrs = append(p.addrs, a.Unmap())
		}
	}
	if len(p.addrs) == 0 {
		if s, _, _ := unstructured.NestedString(u.Object, "status", "podIP"); s != "" {
			if a, err := netip.ParseAddr(s); err == nil {
				p.addrs = append(p.addrs, a.Unmap())
			}
		}
	}
	return p
}

// readPolicy returns the object's selectors and decrypt lists. ok is false
// for an object that applies to nothing: no http section, mode "off", or a
// selector that does not parse.
func readPolicy(u *unstructured.Unstructured) (policy, bool) {
	var spec v1alpha1.PolicySpec
	var podSel metav1.LabelSelector
	var nsSel *metav1.LabelSelector
	p := policy{namespace: u.GetNamespace()}
	switch u.GetKind() {
	case "SandboxPolicy":
		var obj v1alpha1.SandboxPolicy
		if runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &obj) != nil {
			return policy{}, false
		}
		spec, podSel = obj.Spec.PolicySpec, obj.Spec.Selector.PodSelector
	case "ClusterSandboxPolicy":
		var obj v1alpha1.ClusterSandboxPolicy
		if runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &obj) != nil {
			return policy{}, false
		}
		spec, podSel, nsSel = obj.Spec.PolicySpec, obj.Spec.Selector.PodSelector, obj.Spec.Selector.NamespaceSelector
		p.cluster, p.namespace = true, ""
		if nsSel == nil {
			// The field is required. Without it the object selects nothing.
			return policy{}, false
		}
	default:
		return policy{}, false
	}
	if spec.HTTP == nil || spec.Mode == "off" {
		return policy{}, false
	}
	var err error
	if p.pods, err = metav1.LabelSelectorAsSelector(&podSel); err != nil {
		return policy{}, false
	}
	if nsSel != nil {
		if p.spaces, err = metav1.LabelSelectorAsSelector(nsSel); err != nil {
			return policy{}, false
		}
	}
	if spec.HTTP.Decrypt != nil {
		p.decrypt = *spec.HTTP.Decrypt
	}
	return p, true
}

func (p policy) selects(pod podInfo, namespaceLabels map[string]map[string]string) bool {
	if p.cluster {
		nl, known := namespaceLabels[pod.namespace]
		if !known || !p.spaces.Matches(labels.Set(nl)) {
			return false
		}
	} else if p.namespace != pod.namespace {
		return false
	}
	return p.pods.Matches(labels.Set(pod.labels))
}

// build makes the snapshot for node from the objects given. A pod is left
// out when it is on another node, has finished or has no address yet. A pod
// on the host network is never matched for decryption: its connections carry
// the node's address, which every other host process shares.
func build(node string, pods, namespaces, policies []*unstructured.Unstructured) Snapshot {
	nsLabels := map[string]map[string]string{}
	for _, n := range namespaces {
		l := n.GetLabels()
		if l == nil {
			l = map[string]string{}
		}
		nsLabels[n.GetName()] = l
	}
	var applying []policy
	for _, u := range policies {
		if p, ok := readPolicy(u); ok {
			applying = append(applying, p)
		}
	}
	var snap Snapshot
	onNode := map[netip.Addr]bool{}
	for _, u := range pods {
		pod := readPod(u)
		if (node != "" && pod.node != node) || pod.finished || pod.hostNetwork || len(pod.addrs) == 0 {
			continue
		}
		for _, a := range pod.addrs {
			onNode[a] = true
		}
		out := Pod{Namespace: pod.namespace, Name: pod.name, Addrs: pod.addrs}
		selected := false
		for _, p := range applying {
			if !p.selects(pod, nsLabels) {
				continue
			}
			selected = true
			out.Exact = append(out.Exact, p.decrypt.ExactHosts...)
			out.Patterns = append(out.Patterns, p.decrypt.HostPatterns...)
			out.Passthrough = append(out.Passthrough, p.decrypt.Passthrough...)
		}
		if !selected {
			continue
		}
		out.Exact, out.Patterns, out.Passthrough = uniq(out.Exact), uniq(out.Patterns), uniq(out.Passthrough)
		sort.Slice(out.Addrs, func(i, j int) bool { return out.Addrs[i].Less(out.Addrs[j]) })
		snap.Pods = append(snap.Pods, out)
	}
	sort.Slice(snap.Pods, func(i, j int) bool {
		a, b := snap.Pods[i], snap.Pods[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	for a := range onNode {
		snap.OnNode = append(snap.OnNode, a)
	}
	sort.Slice(snap.OnNode, func(i, j int) bool { return snap.OnNode[i].Less(snap.OnNode[j]) })
	return snap
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
