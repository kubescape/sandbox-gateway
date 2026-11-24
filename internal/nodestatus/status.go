// Package nodestatus writes the gateway's state on this node to the cluster,
// as a SandboxGatewayNodeStatus object named after the node.
//
// The object is a snapshot, not a log: every field is written each time, and
// a reader has to look at observedAt to know how old it is. The node
// controller is its only writer.
package nodestatus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/kubescape/sandbox-gateway/internal/ca"
	"github.com/kubescape/sandbox-gateway/internal/envoyadmin"
	"github.com/kubescape/sandbox-gateway/internal/hostset"
)

// The resources the writer touches. The service account needs get and create
// on the first, update on its status subresource, and get on nodes.
var (
	Statuses = v1alpha1.SchemeGroupVersion.WithResource("sandboxgatewaynodestatuses")
	Nodes    = schema.GroupVersionResource{Version: "v1", Resource: "nodes"}
)

// overloadFilter selects the gauges that say an overload action is in force.
const overloadFilter = `^overload\..*\.active$`

// Processor is what the processor's health path reports.
type Processor struct {
	Up                bool
	Evaluator         string // "available" or "unavailable"
	DegradedDecisions int64
}

// ProbeProcessor asks the processor's health socket. A processor that does
// not answer 200 is down; that is not an error.
func ProbeProcessor(socket string) func(ctx context.Context) Processor {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 1,
	}}
	return func(ctx context.Context) Processor {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://processor/healthz/processor", nil)
		if err != nil {
			return Processor{}
		}
		resp, err := client.Do(req)
		if err != nil {
			return Processor{}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return Processor{}
		}
		var body struct {
			Evaluator         string `json:"evaluator"`
			DegradedDecisions int64  `json:"degradedDecisions"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body) != nil {
			return Processor{Up: true}
		}
		return Processor{Up: true, Evaluator: body.Evaluator, DegradedDecisions: body.DegradedDecisions}
	}
}

// Sources is where the status comes from. Every field must be set.
type Sources struct {
	// Envoy returns Envoy's version and whether it is live.
	Envoy func(ctx context.Context) (envoyadmin.Info, error)
	// Stats reads Envoy stats by filter, for the overload gauges.
	Stats func(ctx context.Context, filter string) (map[string]int64, error)
	// Processor probes the processor's health path.
	Processor func(ctx context.Context) Processor
	// Hosts and Rejected come from the host set.
	Hosts    func() hostset.Counts
	Rejected func() []string
	// Certs is the authority's state.
	Certs func() ca.State
}

// Writer keeps the object current. Set every exported field before Run.
type Writer struct {
	Client dynamic.Interface
	// Node is the node's name, and the object's.
	Node    string
	Sources Sources
	Log     *slog.Logger
	// Every is the longest time between writes. Default 30s.
	Every time.Duration
	// MinGap is the shortest time between writes, however fast the state
	// changes. Default 5s.
	MinGap time.Duration
	Now    func() time.Time

	mu       sync.Mutex
	last     *v1alpha1.GatewayNodeStatus // as written last, without observedAt
	lastAt   time.Time
	degraded int64 // last count the processor reported
}

// Build reads every source and returns the status as of now.
func (w *Writer) Build(ctx context.Context) v1alpha1.GatewayNodeStatus {
	now := w.now()
	st := v1alpha1.GatewayNodeStatus{
		Processor:  v1alpha1.GatewayProcessorStatus{Evaluator: v1alpha1.GatewayEvaluatorUnavailable},
		ObservedAt: metav1.NewTime(now.UTC()),
	}
	if info, err := w.Sources.Envoy(ctx); err == nil {
		st.Envoy = v1alpha1.GatewayEnvoyStatus{Up: info.Live, Version: info.Version}
	}
	if stats, err := w.Sources.Stats(ctx, overloadFilter); err == nil {
		for _, active := range stats {
			if active > 0 {
				st.Overloaded = true
				break
			}
		}
	}
	p := w.Sources.Processor(ctx)
	st.Processor.Up = p.Up
	if p.Up && p.Evaluator == string(v1alpha1.GatewayEvaluatorAvailable) {
		st.Processor.Evaluator = v1alpha1.GatewayEvaluatorAvailable
	}
	// The count is the processor's own and restarts with it. While the
	// processor is down the last count it reported stays.
	w.mu.Lock()
	if p.Up {
		w.degraded = p.DegradedDecisions
	}
	st.DegradedDecisions = w.degraded
	w.mu.Unlock()

	counts := w.Sources.Hosts()
	st.Hosts = v1alpha1.GatewayHostCounts{Exact: int64(counts.Exact), Learned: int64(counts.Learned), Cap: int64(counts.Cap)}
	st.PassedThroughOverCap = int64(counts.OverCap)
	st.Evictions = counts.Evictions
	rejected := w.Sources.Rejected()
	if len(rejected) > v1alpha1.MaxStatusRejectedPatterns {
		rejected = rejected[:v1alpha1.MaxStatusRejectedPatterns]
	}
	st.RejectedPatterns = append([]string(nil), rejected...)
	if certs := w.Sources.Certs(); !certs.ValidUntil.IsZero() {
		until := metav1.NewTime(certs.ValidUntil.UTC())
		st.DecryptValidUntil = &until
	}
	return st
}

func (w *Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// same compares two statuses apart from the time they were observed.
func same(a, b v1alpha1.GatewayNodeStatus) bool {
	a.ObservedAt, b.ObservedAt = metav1.Time{}, metav1.Time{}
	return reflect.DeepEqual(a, b)
}

// Tick builds the status and writes it when it is due: at once when it
// changed, unless the last write was under MinGap ago, and otherwise every
// Every. It reports whether it wrote.
func (w *Writer) Tick(ctx context.Context) (wrote bool, err error) {
	every, gap := w.Every, w.MinGap
	if every <= 0 {
		every = 30 * time.Second
	}
	if gap <= 0 {
		gap = 5 * time.Second
	}
	st := w.Build(ctx)
	now := w.now()
	w.mu.Lock()
	last, lastAt := w.last, w.lastAt
	w.mu.Unlock()
	if last != nil {
		since := now.Sub(lastAt)
		if since < gap || (same(*last, st) && since < every) {
			return false, nil
		}
	}
	if err := w.write(ctx, st); err != nil {
		return false, err
	}
	w.mu.Lock()
	w.last, w.lastAt = &st, now
	w.mu.Unlock()
	return true, nil
}

// Run writes the status until ctx ends.
func (w *Writer) Run(ctx context.Context) {
	gap := w.MinGap
	if gap <= 0 {
		gap = 5 * time.Second
	}
	t := time.NewTicker(gap)
	defer t.Stop()
	for {
		if _, err := w.Tick(ctx); err != nil && ctx.Err() == nil {
			w.Log.Error("write the gateway node status", "node", w.Node, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// write creates the object if it is missing, then puts the status
// subresource with the resource version it just read.
func (w *Writer) write(ctx context.Context, st v1alpha1.GatewayNodeStatus) error {
	res := w.Client.Resource(Statuses)
	obj, err := res.Get(ctx, w.Node, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		obj, err = res.Create(ctx, w.empty(ctx), metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			obj, err = res.Get(ctx, w.Node, metav1.GetOptions{})
		}
	}
	if err != nil {
		return fmt.Errorf("nodestatus: read or create %s: %w", w.Node, err)
	}
	status, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&st)
	if err != nil {
		return err
	}
	obj = obj.DeepCopy()
	if err := unstructured.SetNestedMap(obj.Object, status, "status"); err != nil {
		return err
	}
	if _, err := res.UpdateStatus(ctx, obj, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("nodestatus: update the status of %s: %w", w.Node, err)
	}
	return nil
}

// empty is the object as it is created: a name and, when the Node can be
// read, an owner reference to it, so the object goes when the node does.
func (w *Writer) empty(ctx context.Context) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": v1alpha1.SchemeGroupVersion.String(),
		"kind":       "SandboxGatewayNodeStatus",
		"metadata":   map[string]any{"name": w.Node},
	}}
	node, err := w.Client.Resource(Nodes).Get(ctx, w.Node, metav1.GetOptions{})
	if err != nil {
		// The object is still worth writing. A reader tells a stale one by
		// its observedAt.
		w.Log.Warn("cannot read the Node; the status object is created without an owner", "node", w.Node, "error", err)
		return obj
	}
	// Not a controller reference and not blocking: deleting the Node must
	// never wait on this object.
	obj.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: "v1", Kind: "Node", Name: node.GetName(), UID: node.GetUID(),
	}})
	return obj
}
