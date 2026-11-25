package extproc

import (
	"strings"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
	"github.com/kubescape/sandbox-gateway/internal/record"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// C7 is the transaction as the verdict record (contract C7). The JSON log
// line keeps the full Record; this is what goes to OTLP.
func (r Record) C7() record.Record {
	out := record.Record{
		Provider:                r.Provider,
		Model:                   r.Model,
		WouldDeny:               r.WouldDeny,
		Degraded:                r.Degraded,
		UpstreamContentEncoding: r.ContentEncoding,
		DestinationState:        record.DestinationInspected,
		Verdict:                 plugin.ActionAllow,
	}
	switch v := r.Verdict; {
	case v != nil:
		out.Verdict, out.Mode, out.Rule, out.Origin = v.Action, v.Mode, v.Rule, v.Origin
		out.CRDUID, out.CRDRevision = v.PolicyUID, v.PolicyRevision
	case r.Ended == "rejected":
		// Refused before any policy applied: the connection is not one the
		// processor can attribute to a bound pod.
		out.Verdict, out.Mode = plugin.ActionDeny, plugin.ModeEnforce
		out.Rule = "framework." + strings.ReplaceAll(r.RejectReason, "_", "-")
	}
	if r.Ended == "denied" || r.Ended == "rejected" {
		out.DestinationState = record.DestinationBlocked
	}
	if id := r.Identity; id != nil {
		out.FailPosture = id.Posture
		out.FailOpenWindow = id.Gate != conntable.GateRedirecting
		out.Namespace, out.Pod, out.Container = id.Namespace, id.Pod, id.Container
		out.ControllerKind, out.ControllerName = id.ControllerKind, id.ControllerName
		out.ConnLocalAddr, out.ConnLocalPort, out.OrigDst = id.ConnLocalAddr, id.ConnLocalPort, id.OrigDst
	}
	g := map[string]any{
		"transaction_id":       r.TransactionID,
		"authority":            r.Authority,
		"method":               r.Method,
		"path":                 r.Path,
		"protocol":             r.Protocol,
		"status":               r.Status,
		"ended":                r.Ended,
		"request_bytes":        r.RequestBytes,
		"response_bytes":       r.ResponseBytes,
		"response_chunks":      r.ResponseChunks,
		"sse_events":           r.SSEEvents,
		"eventstream_frames":   r.EventStreamFrames,
		"stop_reason":          r.StopReason,
		"first_chunk_after_ms": r.FirstChunkAfterMs,
		"chunk_proc_max_us":    r.ChunkProcMaxUs,
		"chunk_proc_avg_us":    r.ChunkProcAvgUs,
		"early_eos":            r.EarlyEOS,
		"watchdog_fired":       r.WatchdogFired,
	}
	for k, v := range map[string]string{
		"reject_reason": r.RejectReason, "ppv2_ignored": r.PPv2Ignored, "evaluator_error": r.EvaluatorError,
	} {
		if v != "" {
			g[k] = v
		}
	}
	if id := r.Identity; id != nil {
		g["binding_id"] = int(id.BindingID)
		g["cgroup_id"] = int64(id.CgroupID) //nolint:gosec // an id, carried as is
		g["pid"] = int(id.PID)
		if id.LookupFailingSince != "" {
			g["lookup_failing_since"] = id.LookupFailingSince
		}
		if id.LookupError != "" {
			g["lookup_error"] = id.LookupError
		}
	}
	if ws := r.WebSocket; ws != nil {
		g["ws_messages_in"], g["ws_messages_out"] = ws.MessagesIn, ws.MessagesOut
		g["ws_bytes_in"], g["ws_bytes_out"] = ws.BytesIn, ws.BytesOut
	}
	out.Gateway = g
	return out
}
