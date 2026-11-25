package otlpemit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
)

// The backend's ingester keys records on the "account" resource attribute
// (SUB-9954), so the export must carry it, with the node and the family.
func TestExportCarriesTenantAndFamily(t *testing.T) {
	got := make(chan *collogs.ExportLogsServiceRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		req := &collogs.ExportLogsServiceRequest{}
		if err := proto.Unmarshal(b, req); err != nil {
			t.Error(err)
		}
		got <- req
	}))
	defer srv.Close()

	e := New(srv.URL, "node-a", "acct-1")
	e.Add(time.Now(), map[string]any{"verdict": "allow"})
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	rl := (<-got).GetResourceLogs()[0]
	res := map[string]string{}
	for _, kv := range rl.GetResource().GetAttributes() {
		res[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	if res["account"] != "acct-1" || res["k8s.node.name"] != "node-a" || res["service.name"] != "sandbox-egress-gateway" {
		t.Fatalf("resource attributes: %v", res)
	}
	sl := rl.GetScopeLogs()[0]
	if sl.GetScope().GetName() != EventFamily || sl.GetLogRecords()[0].GetEventName() != EventFamily {
		t.Fatalf("scope %q, event %q", sl.GetScope().GetName(), sl.GetLogRecords()[0].GetEventName())
	}
}
