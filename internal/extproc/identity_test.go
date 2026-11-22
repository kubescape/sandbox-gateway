package extproc

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/lookup"
)

// testSource is the pod socket address the test requests arrive from.
const testSource = "10.0.0.5:4242"

const testCgroup = 4711

// fakeTable is an in-memory conntable.Table that counts lookups.
type fakeTable struct {
	mu        sync.Mutex
	conns     map[conntable.Key]conntable.Conn
	bindings  map[uint64]conntable.Binding
	connCalls int
	err       error
}

func newTable() *fakeTable {
	k, _ := conntable.ParseKey(testSource)
	return &fakeTable{
		conns: map[conntable.Key]conntable.Conn{k: {CgroupID: testCgroup, PID: 99, BindingID: 12,
			OrigDst: netip.MustParseAddrPort("160.79.104.10:443")}},
		bindings: map[uint64]conntable.Binding{testCgroup: {BindingID: 12, Posture: conntable.PostureDeny}},
	}
}

func (f *fakeTable) Conn(k conntable.Key) (conntable.Conn, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connCalls++
	if f.err != nil {
		return conntable.Conn{}, false, f.err
	}
	c, ok := f.conns[k]
	return c, ok, nil
}

func (f *fakeTable) Binding(id uint64) (conntable.Binding, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.bindings[id]
	return b, ok, nil
}

func testWorkload() lookup.Workload {
	w := lookup.Workload{Namespace: "agents", Pod: "coder-7d9f", Container: "main", BindingID: 12,
		Policies: []lookup.PolicyRef{{UID: "uid-a", Generation: 4}}}
	w.Controller.Kind, w.Controller.Name = "Deployment", "coder"
	return w
}

func fixedLookup(w lookup.Workload, failing time.Time, err error) LookupFunc {
	return func(context.Context, uint64) (lookup.Workload, time.Time, error) { return w, failing, err }
}

func srcAttrs(addr string) map[string]*structpb.Struct {
	if addr == "" {
		return nil
	}
	s, _ := structpb.NewStruct(map[string]any{"source.address": addr})
	return map[string]*structpb.Struct{"envoy.filters.http.ext_proc": s}
}

// headersFrom sends request headers that arrive from addr and returns the answer.
func headersFrom(t *testing.T, st extprocv3.ExternalProcessor_ProcessClient, addr string) *extprocv3.ProcessingResponse {
	t.Helper()
	must(t, st.Send(&extprocv3.ProcessingRequest{
		Attributes: srcAttrs(addr),
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: hdrs(":method", "POST", ":path", "/v1/messages", ":authority", "api.anthropic.com")}}}))
	return recv(t, st)
}

func wantRejected(t *testing.T, r *extprocv3.ProcessingResponse, h *harness, reason string) {
	t.Helper()
	im := r.GetImmediateResponse()
	if im.GetStatus().GetCode() != 403 || im.GetDetails() != reason {
		t.Fatalf("response = %v, want an immediate 403 with details %q", r, reason)
	}
	rec := h.waitRecords(t, 1)[0]
	if rec.Ended != "rejected" || rec.RejectReason != reason || rec.Identity != nil {
		t.Fatalf("record: ended=%q reason=%q identity=%+v", rec.Ended, rec.RejectReason, rec.Identity)
	}
}

func TestConnsMissRejected(t *testing.T) {
	st, h := start(t, Config{})
	wantRejected(t, headersFrom(t, st, "10.0.0.6:1111"), h, "no_connection_entry")
}

func TestNoSourceAddressRejected(t *testing.T) {
	for _, addr := range []string{"", "not-an-address", "/run/envoy.sock"} {
		st, h := start(t, Config{})
		wantRejected(t, headersFrom(t, st, addr), h, "no_source_address")
	}
}

func TestNoTableRejectsEverything(t *testing.T) {
	st, h := startRaw(t, Config{})
	wantRejected(t, headersFrom(t, st, testSource), h, "no_connection_table")
}

func TestTableErrorRejected(t *testing.T) {
	tbl := newTable()
	tbl.err = errors.New("map read failed")
	st, h := start(t, Config{Conns: tbl})
	wantRejected(t, headersFrom(t, st, testSource), h, "connection_table_error")
}

func TestConnWithoutBindingRejected(t *testing.T) {
	tbl := newTable()
	delete(tbl.bindings, testCgroup)
	st, h := start(t, Config{Conns: tbl})
	wantRejected(t, headersFrom(t, st, testSource), h, "not_bound")
}

// Review focus: the connection is in the table but node-agent says the pod was
// unbound in between.
func TestUnboundCgroupRejected(t *testing.T) {
	st, h := start(t, Config{Lookup: fixedLookup(lookup.Workload{}, time.Time{}, lookup.ErrNotBound)})
	wantRejected(t, headersFrom(t, st, testSource), h, "not_bound")
}

func TestIdentityFromTable(t *testing.T) {
	st, h := start(t, Config{})
	r := headersFrom(t, st, "[::ffff:10.0.0.5]:4242") // the mapped spelling of testSource
	if r.GetRequestHeaders() == nil {
		t.Fatalf("response = %v, want the request to continue", r)
	}
	audit := r.GetDynamicMetadata().GetFields()[AuditNS].GetStructValue().GetFields()
	if audit["pod"].GetStringValue() != "coder-7d9f" || audit["namespace"].GetStringValue() != "agents" {
		t.Fatalf("audit metadata = %v", audit)
	}
	must(t, st.CloseSend())
	id := h.waitRecords(t, 1)[0].Identity
	if id == nil {
		t.Fatal("no identity on the record")
	}
	want := Identity{Namespace: "agents", Pod: "coder-7d9f", Container: "main", ControllerKind: "Deployment",
		ControllerName: "coder", BindingID: 12, Posture: "deny", CgroupID: testCgroup, PID: 99,
		ConnLocalAddr: "10.0.0.5", ConnLocalPort: 4242, OrigDst: "160.79.104.10:443"}
	if *id != want {
		t.Fatalf("identity = %+v\nwant       %+v", *id, want)
	}
}

func TestPPv2IgnoredAndFlagged(t *testing.T) {
	st, h := start(t, Config{})
	// A client that speaks PROXY protocol to the listener claims another pod.
	must(t, st.Send(&extprocv3.ProcessingRequest{
		MetadataContext: attrMeta(),
		Attributes:      srcAttrs(testSource),
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: hdrs(":method", "POST", ":path", "/v1/messages", ":authority", "api.anthropic.com")}}}))
	r := recv(t, st)
	audit := r.GetDynamicMetadata().GetFields()[AuditNS].GetStructValue().GetFields()
	if _, ok := audit["pod_uid"]; ok || audit["pod"].GetStringValue() != "coder-7d9f" {
		t.Fatalf("the claimed identity reached the access log: %v", audit)
	}
	must(t, st.CloseSend())
	rec := h.waitRecords(t, 1)[0]
	if rec.Identity.Pod != "coder-7d9f" || rec.PPv2Ignored != "pod_uid=uid-1 pid=4242" {
		t.Fatalf("identity=%+v ppv2_ignored=%q", rec.Identity, rec.PPv2Ignored)
	}
}

// A forged PROXY protocol identity does not get a connection past the table.
func TestPPv2DoesNotReplaceTheTable(t *testing.T) {
	st, h := start(t, Config{})
	must(t, st.Send(&extprocv3.ProcessingRequest{
		MetadataContext: attrMeta(),
		Attributes:      srcAttrs("10.0.0.6:1111"),
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: hdrs(":method", "POST", ":path", "/v1/messages", ":authority", "api.anthropic.com")}}}))
	wantRejected(t, recv(t, st), h, "no_connection_entry")
}

// Review focus: nothing is cached by address and port, because the kernel
// reuses them. Each request reads the table again.
func TestEveryRequestReadsTheTable(t *testing.T) {
	tbl := newTable()
	cfg := Config{Conns: tbl}
	st, _ := start(t, cfg)
	if headersFrom(t, st, testSource).GetRequestHeaders() == nil {
		t.Fatal("first request did not continue")
	}
	// The same address and port now belong to another pod's connection.
	k, _ := conntable.ParseKey(testSource)
	tbl.mu.Lock()
	tbl.conns[k] = conntable.Conn{CgroupID: 9000, BindingID: 13, OrigDst: netip.MustParseAddrPort("1.2.3.4:443")}
	tbl.bindings[9000] = conntable.Binding{BindingID: 13, Posture: conntable.PostureAllow}
	tbl.mu.Unlock()
	st2, h2 := start(t, cfg)
	if headersFrom(t, st2, testSource).GetRequestHeaders() == nil {
		t.Fatal("second request did not continue")
	}
	must(t, st2.CloseSend())
	id := h2.waitRecords(t, 1)[0].Identity
	if id.CgroupID != 9000 || id.BindingID != 13 || id.Posture != "allow" {
		t.Fatalf("second connection kept the first one's identity: %+v", id)
	}
	if tbl.connCalls != 2 {
		t.Fatalf("%d table reads for two requests, want 2", tbl.connCalls)
	}
}

// With node-agent's socket down and nothing cached, the kernel half of the
// identity is still known. The request is not rejected here; what a decision
// without a workload does is the policy source's business.
func TestLookupDownKeepsKernelIdentity(t *testing.T) {
	since := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	st, h := start(t, Config{Lookup: fixedLookup(lookup.Workload{}, since, errors.New("dial unix: no such file"))})
	if headersFrom(t, st, testSource).GetRequestHeaders() == nil {
		t.Fatal("request did not continue")
	}
	must(t, st.CloseSend())
	id := h.waitRecords(t, 1)[0].Identity
	if id == nil || id.CgroupID != testCgroup || id.Posture != "deny" || id.Pod != "" || id.LookupError == "" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestLookupServedFromCacheIsMarked(t *testing.T) {
	since := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	st, h := start(t, Config{Lookup: fixedLookup(testWorkload(), since, nil)})
	headersFrom(t, st, testSource)
	must(t, st.CloseSend())
	id := h.waitRecords(t, 1)[0].Identity
	if id.Pod != "coder-7d9f" || id.LookupFailingSince != "2026-11-22T10:00:00Z" {
		t.Fatalf("identity = %+v", id)
	}
}
