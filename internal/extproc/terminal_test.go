package extproc

import (
	"strings"
	"testing"

	"github.com/kubescape/sandbox-gateway/internal/sse"
)

// Review: the tracker holds open OpenAI Responses items too, and those must
// not be closed with Anthropic content_block_stop events.
func TestTerminalEventsCloseOnlyAnthropicBlocks(t *testing.T) {
	tx := &txn{}
	tx.trackEvent(sse.Event{Data: `{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"type":"message"}}`})
	if got := string(tx.terminalEvents()); strings.Contains(got, "content_block_stop") {
		t.Fatalf("Responses stream got Anthropic block stops:\n%s", got)
	}

	tx = &txn{}
	tx.trackEvent(sse.Event{Data: `{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`})
	if got := string(tx.terminalEvents()); !strings.Contains(got, `"type":"content_block_stop","index":2`) {
		t.Fatalf("open Anthropic block not closed:\n%s", got)
	}
}
