package record

import (
	"sort"
	"strings"
	"testing"
)

// c7 is the attribute list of contract C7, verbatim.
var c7 = []string{"crd_uid", "crd_revision", "rule", "origin", "verdict", "mode", "would_deny", "tier",
	"fail_posture", "provider", "model", "destination_state", "degraded", "fail_open_window",
	"upstream_content_encoding", "namespace", "pod", "container", "controller_kind", "controller_name",
	"conn_local_addr", "conn_local_port", "orig_dst", "request_position"}

func full() Record {
	return Record{CRDUID: "uid-a", CRDRevision: 3, Rule: "r1", Origin: "policy", Verdict: "deny", Mode: "enforce",
		WouldDeny: false, FailPosture: "deny", Provider: "anthropic", Model: "claude", DestinationState: DestinationBlocked,
		Degraded: true, FailOpenWindow: true, UpstreamContentEncoding: "gzip",
		Namespace: "agents", Pod: "p", Container: "c", ControllerKind: "Deployment", ControllerName: "d",
		ConnLocalAddr: "10.0.0.7", ConnLocalPort: 40000, OrigDst: "1.2.3.4:443", RequestPosition: 2,
		Gateway: map[string]any{"ended": "denied", "request_bytes": 10}}
}

func TestAttrsMatchC7(t *testing.T) {
	a := full().Attrs()
	var got, extra []string
	for k := range a {
		if strings.HasPrefix(k, "gateway.") {
			extra = append(extra, k)
			continue
		}
		got = append(got, k)
	}
	want := append([]string(nil), c7...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("keys outside gateway.*:\n got %v\nwant %v", got, want)
	}
	if len(extra) != 2 {
		t.Fatalf("gateway keys = %v", extra)
	}
	if a["tier"] != "gateway" {
		t.Fatalf("tier = %v", a["tier"])
	}
}

func TestContentEncodingOnlyWhenNotIdentity(t *testing.T) {
	for enc, want := range map[string]bool{"": false, "identity": false, "IDENTITY": false, "gzip": true, "br": true} {
		r := full()
		r.UpstreamContentEncoding = enc
		if _, ok := r.Attrs()["upstream_content_encoding"]; ok != want {
			t.Errorf("encoding %q: present = %v", enc, ok)
		}
	}
}

func TestRequestPositionOnlyWhenKnown(t *testing.T) {
	r := full()
	r.RequestPosition = 0
	if _, ok := r.Attrs()["request_position"]; ok {
		t.Fatal("an unknown position is in the attributes")
	}
}
