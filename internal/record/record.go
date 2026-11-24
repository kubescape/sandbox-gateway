// Package record is the gateway's verdict record (contract C7): one OTLP log
// record per transaction, family R-L7-GW, with no request or response bytes.
//
// Attrs uses the C7 attribute names verbatim. What the processor measures
// about the stream on top of them (sizes, timings, how it ended) goes under a
// "gateway." prefix, so a reader can tell the contract from the extras.
package record

import "strings"

// Family is the C7 record family.
const Family = "R-L7-GW"

// Tier is what every record from this gateway carries in "tier".
const Tier = "gateway"

// Destination states (C7 destination_state).
const (
	DestinationInspected   = "inspected"   // decrypted, checked and forwarded
	DestinationPassthrough = "passthrough" // not decrypted; the processor never sees these
	DestinationBlocked     = "blocked"     // refused before or while it reached the provider
	DestinationNone        = "none"
)

// Record is one transaction. Each field up to Gateway is one C7 attribute.
type Record struct {
	CRDUID      string
	CRDRevision int64
	Rule        string
	Origin      string
	Verdict     string // allow | deny
	Mode        string // audit | enforce
	WouldDeny   bool
	FailPosture string // allow | deny, from the bindings table
	Provider    string
	Model       string
	// DestinationState is one of the Destination constants.
	DestinationState string
	Degraded         bool
	// FailOpenWindow is set when the pod's health gate was not redirecting
	// (failing open or recovering) when the request arrived.
	FailOpenWindow bool
	// UpstreamContentEncoding is the upstream's Content-Encoding. It is only
	// put in the attributes when it is something other than identity.
	UpstreamContentEncoding string

	Namespace      string
	Pod            string
	Container      string
	ControllerKind string
	ControllerName string

	// The join key: the pod socket's address and port (as in the conns key),
	// where the pod was connecting to, and the request's position on its
	// connection. RequestPosition is 0 when it is not known (HTTP/2), and is
	// then left out of the attributes.
	ConnLocalAddr   string
	ConnLocalPort   uint16
	OrigDst         string
	RequestPosition int

	// Gateway is everything else the processor knows, under "gateway.".
	Gateway map[string]any
}

// Attrs is the record as OTLP log attributes: the C7 names, and Gateway's
// entries prefixed with "gateway.".
func (r Record) Attrs() map[string]any {
	a := map[string]any{
		"crd_uid":           r.CRDUID,
		"crd_revision":      r.CRDRevision,
		"rule":              r.Rule,
		"origin":            r.Origin,
		"verdict":           r.Verdict,
		"mode":              r.Mode,
		"would_deny":        r.WouldDeny,
		"tier":              Tier,
		"fail_posture":      r.FailPosture,
		"provider":          r.Provider,
		"model":             r.Model,
		"destination_state": r.DestinationState,
		"degraded":          r.Degraded,
		"fail_open_window":  r.FailOpenWindow,
		"namespace":         r.Namespace,
		"pod":               r.Pod,
		"container":         r.Container,
		"controller_kind":   r.ControllerKind,
		"controller_name":   r.ControllerName,
		"conn_local_addr":   r.ConnLocalAddr,
		"conn_local_port":   int(r.ConnLocalPort),
		"orig_dst":          r.OrigDst,
	}
	if e := r.UpstreamContentEncoding; e != "" && !strings.EqualFold(e, "identity") {
		a["upstream_content_encoding"] = e
	}
	if r.RequestPosition > 0 {
		a["request_position"] = r.RequestPosition
	}
	for k, v := range r.Gateway {
		a["gateway."+k] = v
	}
	return a
}
