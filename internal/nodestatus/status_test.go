package nodestatus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubescape/sandbox-gateway/internal/ca"
	"github.com/kubescape/sandbox-gateway/internal/envoyadmin"
	"github.com/kubescape/sandbox-gateway/internal/hostset"
)

type world struct {
	envoy     envoyadmin.Info
	envoyErr  error
	overload  map[string]int64
	processor Processor
	counts    hostset.Counts
	rejected  []string
	certs     ca.State
	now       time.Time
}

func newWorld() *world {
	return &world{
		envoy:     envoyadmin.Info{Version: "1.40.2", Live: true},
		overload:  map[string]int64{"overload.envoy.overload_actions.shrink_heap.active": 0},
		processor: Processor{Up: true, Evaluator: "available", DegradedDecisions: 3},
		counts:    hostset.Counts{Exact: 12, Learned: 3, Cap: 256, OverCap: 2, Evictions: 7},
		rejected:  []string{"*.amazonaws.com"},
		certs:     ca.State{CanDecrypt: true, ValidUntil: time.Date(2026, 11, 24, 15, 30, 0, 0, time.UTC)},
		now:       time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC),
	}
}

func node(name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": name},
	}}
	u.SetUID(types.UID("node-uid-1"))
	return u
}

func writer(wd *world, objs ...runtime.Object) (*Writer, *fake.FakeDynamicClient) {
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		Statuses: "SandboxGatewayNodeStatusList", Nodes: "NodeList",
	}, objs...)
	return &Writer{
		Client: client, Node: "node-a", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return wd.now },
		Sources: Sources{
			Envoy:     func(context.Context) (envoyadmin.Info, error) { return wd.envoy, wd.envoyErr },
			Stats:     func(context.Context, string) (map[string]int64, error) { return wd.overload, nil },
			Processor: func(context.Context) Processor { return wd.processor },
			Hosts:     func() hostset.Counts { return wd.counts },
			Rejected:  func() []string { return wd.rejected },
			Certs:     func() ca.State { return wd.certs },
		},
	}, client
}

func read(t *testing.T, client *fake.FakeDynamicClient) (*unstructured.Unstructured, v1alpha1.GatewayNodeStatus) {
	t.Helper()
	obj, err := client.Resource(Statuses).Get(context.Background(), "node-a", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var typed v1alpha1.SandboxGatewayNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &typed); err != nil {
		t.Fatal(err)
	}
	if typed.Status == nil {
		t.Fatal("the object has no status")
	}
	return obj, *typed.Status
}

func TestCreatesTheObjectOwnedByTheNodeAndWritesEveryField(t *testing.T) {
	wd := newWorld()
	w, client := writer(wd, node("node-a"))
	if wrote, err := w.Tick(context.Background()); err != nil || !wrote {
		t.Fatalf("Tick: %v %v", wrote, err)
	}
	obj, st := read(t, client)
	if obj.GetNamespace() != "" || obj.GetName() != "node-a" {
		t.Fatalf("the object is cluster-scoped and named after the node, got %s/%s", obj.GetNamespace(), obj.GetName())
	}
	owners := obj.GetOwnerReferences()
	if len(owners) != 1 || owners[0].Kind != "Node" || owners[0].Name != "node-a" || owners[0].UID != "node-uid-1" {
		t.Fatalf("owner references = %+v", owners)
	}
	if owners[0].BlockOwnerDeletion != nil || owners[0].Controller != nil {
		t.Fatal("the reference must not block the Node's deletion or claim to control")
	}
	until := metav1.NewTime(wd.certs.ValidUntil)
	want := v1alpha1.GatewayNodeStatus{
		Envoy:                v1alpha1.GatewayEnvoyStatus{Up: true, Version: "1.40.2"},
		Processor:            v1alpha1.GatewayProcessorStatus{Up: true, Evaluator: v1alpha1.GatewayEvaluatorAvailable},
		Overloaded:           false,
		Hosts:                v1alpha1.GatewayHostCounts{Exact: 12, Learned: 3, Cap: 256},
		RejectedPatterns:     []string{"*.amazonaws.com"},
		PassedThroughOverCap: 2,
		Evictions:            7,
		DegradedDecisions:    3,
		DecryptValidUntil:    &until,
		ObservedAt:           metav1.NewTime(wd.now),
	}
	// Times come back in the local zone; compare them as instants.
	if st.DecryptValidUntil == nil || !st.DecryptValidUntil.Time.Equal(wd.certs.ValidUntil) || !st.ObservedAt.Time.Equal(wd.now) {
		t.Fatalf("decryptValidUntil = %v, observedAt = %v", st.DecryptValidUntil, st.ObservedAt)
	}
	st.DecryptValidUntil, want.DecryptValidUntil = nil, nil
	if !same(st, want) {
		t.Fatalf("status = %+v\nwant     %+v", st, want)
	}
	if raw, _, _ := unstructured.NestedString(obj.Object, "status", "observedAt"); raw != "2026-11-24T15:00:00Z" {
		t.Fatalf("observedAt is stored as %q, want UTC RFC 3339", raw)
	}
	// False and zero are facts about the node: they are written, not left out.
	status, _, _ := unstructured.NestedMap(obj.Object, "status")
	for _, key := range []string{"envoy", "processor", "overloaded", "hosts", "passedThroughOverCap", "evictions", "degradedDecisions", "observedAt"} {
		if _, ok := status[key]; !ok {
			t.Errorf("status.%s is missing", key)
		}
	}
}

func TestUpdateUsesTheResourceVersionItRead(t *testing.T) {
	wd := newWorld()
	existing := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kubescape.io/v1alpha1", "kind": "SandboxGatewayNodeStatus",
		"metadata": map[string]any{"name": "node-a", "resourceVersion": "41"},
	}}
	w, client := writer(wd, existing)
	var updateRV, subresource string
	creates := 0
	client.PrependReactor("*", "sandboxgatewaynodestatuses", func(a k8stesting.Action) (bool, runtime.Object, error) {
		// Create and update actions have the same Go shape; the verb tells them apart.
		switch a.GetVerb() {
		case "update":
			act := a.(k8stesting.UpdateAction)
			subresource = act.GetSubresource()
			updateRV = act.GetObject().(*unstructured.Unstructured).GetResourceVersion()
		case "create":
			creates++
		}
		return false, nil, nil
	})
	if _, err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if creates != 0 {
		t.Fatal("an existing object must not be created again")
	}
	if subresource != "status" || updateRV != "41" {
		t.Fatalf("update went to subresource %q with resourceVersion %q", subresource, updateRV)
	}
}

func TestStatusIsWrittenWithoutAnOwnerWhenTheNodeCannotBeRead(t *testing.T) {
	wd := newWorld()
	w, client := writer(wd) // no Node object
	if _, err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	obj, _ := read(t, client)
	if len(obj.GetOwnerReferences()) != 0 {
		t.Fatal("no Node, no owner")
	}
}

func TestDownProcessesAreReportedDown(t *testing.T) {
	wd := newWorld()
	w, client := writer(wd, node("node-a"))
	_, _ = w.Tick(context.Background())

	wd.now = wd.now.Add(10 * time.Second)
	wd.envoyErr = errors.New("admin socket gone")
	wd.processor = Processor{}
	wd.overload = map[string]int64{"overload.envoy.overload_actions.shrink_heap.active": 1}
	wd.certs = ca.State{}
	if wrote, err := w.Tick(context.Background()); err != nil || !wrote {
		t.Fatalf("a change is written: %v %v", wrote, err)
	}
	_, st := read(t, client)
	if st.Envoy.Up || st.Envoy.Version != "" {
		t.Fatalf("envoy = %+v", st.Envoy)
	}
	if st.Processor.Up || st.Processor.Evaluator != v1alpha1.GatewayEvaluatorUnavailable {
		t.Fatalf("processor = %+v", st.Processor)
	}
	if !st.Overloaded {
		t.Fatal("an active overload action must show")
	}
	if st.DegradedDecisions != 3 {
		t.Fatalf("the last count the processor reported stays while it is down, got %d", st.DegradedDecisions)
	}
	if st.DecryptValidUntil != nil {
		t.Fatal("no intermediate, no decryptValidUntil")
	}
}

func TestEvaluatorIsUnavailableUnlessTheProcessorSaysAvailable(t *testing.T) {
	wd := newWorld()
	wd.processor = Processor{Up: true, Evaluator: "unavailable"}
	w, _ := writer(wd)
	if st := w.Build(context.Background()); !st.Processor.Up || st.Processor.Evaluator != v1alpha1.GatewayEvaluatorUnavailable {
		t.Fatalf("processor = %+v", st.Processor)
	}
	wd.processor = Processor{Up: true, Evaluator: "something-else"}
	if st := w.Build(context.Background()); st.Processor.Evaluator != v1alpha1.GatewayEvaluatorUnavailable {
		t.Fatalf("an unknown value is not available: %+v", st.Processor)
	}
}

func TestRejectedPatternsAreCapped(t *testing.T) {
	wd := newWorld()
	wd.rejected = nil
	for i := 0; i < 100; i++ {
		wd.rejected = append(wd.rejected, fmt.Sprintf("*.r%03d.example", i))
	}
	w, _ := writer(wd)
	if st := w.Build(context.Background()); len(st.RejectedPatterns) != v1alpha1.MaxStatusRejectedPatterns {
		t.Fatalf("%d rejected patterns, the cap is %d", len(st.RejectedPatterns), v1alpha1.MaxStatusRejectedPatterns)
	}
}

func TestWriteCadence(t *testing.T) {
	wd := newWorld()
	w, _ := writer(wd, node("node-a"))
	tick := func() bool {
		t.Helper()
		wrote, err := w.Tick(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return wrote
	}
	if !tick() {
		t.Fatal("the first tick writes")
	}
	wd.now = wd.now.Add(10 * time.Second)
	if tick() {
		t.Fatal("nothing changed and 30s have not passed")
	}
	wd.now = wd.now.Add(21 * time.Second)
	if !tick() {
		t.Fatal("after 30s the status is written again, so observedAt stays fresh")
	}
	// A change is written at once, but not within 5s of the last write.
	wd.counts.Learned++
	wd.now = wd.now.Add(2 * time.Second)
	if tick() {
		t.Fatal("under 5s since the last write")
	}
	wd.now = wd.now.Add(4 * time.Second)
	if !tick() {
		t.Fatal("a change is written once 5s have passed")
	}
}

func TestProbeProcessor(t *testing.T) {
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "p.sock")
	probe := ProbeProcessor(sock)
	if p := probe(context.Background()); p.Up {
		t.Fatal("no socket: down")
	}
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	status := http.StatusServiceUnavailable
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz/processor", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"evaluator":"available","degradedDecisions":5,"stuckEvaluatorCalls":0}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()
	defer func() { _ = srv.Close() }()
	if p := probe(context.Background()); p.Up {
		t.Fatal("503 before the first sync: down")
	}
	status = http.StatusOK
	if p := probe(context.Background()); !p.Up || p.Evaluator != "available" || p.DegradedDecisions != 5 {
		t.Fatalf("probe = %+v", p)
	}
}
