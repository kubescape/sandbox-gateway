// Package otlpemit is stage 4 (gap 6): transaction records leave the node as
// OTLP log records, the transport the sandbox pipeline already ingests.
// Records are batched and POSTed as protobuf to <endpoint>/v1/logs.
//
// Event family: R-L7-GW (new; the backend would need to accept it). Identity
// attributes reuse the sandbox event schema's keys where the gateway has them;
// cgroup id and pid come from the 5-tuple table, and pod / container names would
// be resolved from them by the node agent.
package otlpemit

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resv1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

// EventFamily is the event name and family of gateway records.
const EventFamily = "R-L7-GW"

// Exporter batches records and sends them.
type Exporter struct {
	endpoint string
	resource []*commonv1.KeyValue
	client   *http.Client
	mu       sync.Mutex
	batch    []*logsv1.LogRecord
	Sent     int
	Failed   int
}

// New returns an exporter for an OTLP/HTTP endpoint (e.g. http://collector:4318).
func New(endpoint, nodeName, accountID string) *Exporter {
	return &Exporter{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
		resource: []*commonv1.KeyValue{
			kv("service.name", "sandbox-egress-gateway"), kv("schema_version", "0.1"),
			kv("k8s.node.name", nodeName), kv("account", accountID),
		},
	}
}

// Add queues one record. attrs values are strings, ints, floats or bools.
func (e *Exporter) Add(at time.Time, attrs map[string]any) {
	r := &logsv1.LogRecord{TimeUnixNano: uint64(at.UnixNano()), ObservedTimeUnixNano: uint64(time.Now().UnixNano()),
		EventName: EventFamily, SeverityText: "INFO"}
	r.Attributes = append(r.Attributes, kv("event.family", EventFamily))
	for k, v := range attrs {
		if a := anyKV(k, v); a != nil {
			r.Attributes = append(r.Attributes, a)
		}
	}
	e.mu.Lock()
	e.batch = append(e.batch, r)
	e.mu.Unlock()
}

// Flush sends what is queued.
func (e *Exporter) Flush() error {
	e.mu.Lock()
	batch := e.batch
	e.batch = nil
	e.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	req := &collogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
		Resource:  &resv1.Resource{Attributes: e.resource},
		ScopeLogs: []*logsv1.ScopeLogs{{Scope: &commonv1.InstrumentationScope{Name: "egress-gateway-poc"}, LogRecords: batch}},
	}}}
	b, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := e.client.Post(e.endpoint+"/v1/logs", "application/x-protobuf", bytes.NewReader(b))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			err = fmt.Errorf("otlp: status %d", resp.StatusCode)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.Failed += len(batch)
		return err
	}
	e.Sent += len(batch)
	return nil
}

// Run flushes every interval until stop is closed.
func (e *Exporter) Run(interval time.Duration, stop <-chan struct{}, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			_ = e.Flush()
			return
		case <-t.C:
			if err := e.Flush(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

func kv(k, v string) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: v}}}
}

func anyKV(k string, v any) *commonv1.KeyValue {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return kv(k, x)
	case int:
		return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: int64(x)}}}
	case int64:
		return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: x}}}
	case float64:
		return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_DoubleValue{DoubleValue: x}}}
	case bool:
		return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_BoolValue{BoolValue: x}}}
	}
	return nil
}
