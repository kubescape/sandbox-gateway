package extproc

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/kubescape/sandbox-gateway/internal/eventstream"
)

// bedrockChunk builds one Bedrock InvokeModelWithResponseStream frame carrying
// an Anthropic stream event.
func bedrockChunk(t *testing.T, event string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(event))})
	if err != nil {
		t.Fatal(err)
	}
	return eventstream.Encode(eventstream.Frame{
		Headers: []eventstream.Header{
			eventstream.StringHeader(":event-type", "chunk"),
			eventstream.StringHeader(":content-type", "application/json"),
			eventstream.StringHeader(":message-type", "event"),
		},
		Payload: payload,
	})
}

func TestEventStreamChunkTracksAnthropicEvents(t *testing.T) {
	var wire []byte
	for _, ev := range []string{
		`{"type":"message_start","message":{"id":"m"}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"1"}}`,
		`{"type":"content_block_stop","index":0}`,
		`{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`,
		`{"type":"message_stop"}`,
	} {
		wire = append(wire, bedrockChunk(t, ev)...)
	}
	tx := &txn{es: &eventstream.Decoder{}}
	// Split mid-frame to check reassembly across ext_proc chunks.
	for _, part := range [][]byte{wire[:37], wire[37:200], wire[200:]} {
		if err := tx.eventStreamChunk(part); err != nil {
			t.Fatal(err)
		}
	}
	if tx.rec.EventStreamFrames != 6 || tx.rec.SSEEvents != 6 {
		t.Fatalf("frames=%d events=%d, want 6 and 6", tx.rec.EventStreamFrames, tx.rec.SSEEvents)
	}
	if tx.rec.StopReason != "end_turn" || len(tx.track.Open()) != 0 {
		t.Fatalf("stop=%q open=%v", tx.rec.StopReason, tx.track.Open())
	}
	if tx.es.Pending() != 0 {
		t.Fatalf("pending %d bytes", tx.es.Pending())
	}
}

func TestEventStreamChunkBadCRC(t *testing.T) {
	b := bedrockChunk(t, `{"type":"message_stop"}`)
	b[9] ^= 0xff // corrupt the prelude CRC
	tx := &txn{es: &eventstream.Decoder{}}
	if err := tx.eventStreamChunk(b); err == nil {
		t.Fatal("want a CRC error")
	}
}
