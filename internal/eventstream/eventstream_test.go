package eventstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awses "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// converseStream is a Bedrock ConverseStream response as AWS's own encoder
// writes it: text, a tool call, stop_reason tool_use, usage metadata.
var converseEvents = []struct{ typ, payload string }{
	{"messageStart", `{"role":"assistant","p":"abc"}`},
	{"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Let me look."},"p":"abcd"}`},
	{"contentBlockStop", `{"contentBlockIndex":0,"p":"ab"}`},
	{"contentBlockStart", `{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tooluse_1","name":"bash"}},"p":"a"}`},
	{"contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"cmd\":\"ls\"}"}},"p":"abc"}`},
	{"contentBlockStop", `{"contentBlockIndex":1,"p":"abcdef"}`},
	{"messageStop", `{"stopReason":"tool_use","p":"abcdefg"}`},
	{"metadata", `{"usage":{"inputTokens":12,"outputTokens":30,"totalTokens":42},"metrics":{"latencyMs":420},"p":"ab"}`},
}

func awsFixture(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := awses.NewEncoder()
	for _, e := range converseEvents {
		var h awses.Headers
		h.Set(":event-type", awses.StringValue(e.typ))
		h.Set(":content-type", awses.StringValue("application/json"))
		h.Set(":message-type", awses.StringValue("event"))
		if err := enc.Encode(&buf, awses.Message{Headers: h, Payload: []byte(e.payload)}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// awsDecodeAll decodes with AWS's decoder, which checks both CRCs.
func awsDecodeAll(t *testing.T, b []byte) []awses.Message {
	t.Helper()
	dec := awses.NewDecoder()
	r := bytes.NewReader(b)
	var out []awses.Message
	for r.Len() > 0 {
		m, err := dec.Decode(r, nil)
		if err != nil {
			t.Fatalf("AWS decoder rejected frame %d: %v", len(out), err)
		}
		out = append(out, m)
	}
	return out
}

// Unchanged frames re-encode byte for byte.
func TestRoundTripByteForByte(t *testing.T) {
	fix := awsFixture(t)
	var d Decoder
	frames, raws, err := d.Feed(fix)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != len(converseEvents) || d.Pending() != 0 {
		t.Fatalf("frames %d pending %d", len(frames), d.Pending())
	}
	var re []byte
	for i, f := range frames {
		enc := Encode(f)
		if !bytes.Equal(enc, raws[i]) {
			t.Fatalf("frame %d differs after re-encode", i)
		}
		if f.Get(":event-type") != converseEvents[i].typ {
			t.Fatalf("frame %d event-type %q", i, f.Get(":event-type"))
		}
		re = append(re, enc...)
	}
	if !bytes.Equal(re, fix) {
		t.Fatal("stream differs after re-encode")
	}
}

// Frames split at any byte boundary decode the same.
func TestEverySplitPoint(t *testing.T) {
	fix := awsFixture(t)
	for i := 0; i <= len(fix); i++ {
		var d Decoder
		a, _, err := d.Feed(fix[:i])
		if err != nil {
			t.Fatalf("split %d: %v", i, err)
		}
		b, _, err := d.Feed(fix[i:])
		if err != nil {
			t.Fatalf("split %d: %v", i, err)
		}
		if len(a)+len(b) != len(converseEvents) {
			t.Fatalf("split %d: %d frames", i, len(a)+len(b))
		}
	}
}

// A rewrite (drop the tool call, renumber nothing after it, stop_reason
// end_turn) produces frames AWS's decoder accepts.
func TestRewriteAcceptedByAWSDecoder(t *testing.T) {
	var d Decoder
	frames, _, err := d.Feed(awsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, f := range frames {
		switch {
		case strings.Contains(string(f.Payload), `"contentBlockIndex":1`):
			continue // the tool call block
		case f.Get(":event-type") == "messageStop":
			f.Payload = []byte(`{"stopReason":"end_turn","p":"abcdefg"}`)
		}
		out = append(out, Encode(f)...)
	}
	msgs := awsDecodeAll(t, out)
	if len(msgs) != len(converseEvents)-3 {
		t.Fatalf("AWS decoded %d frames", len(msgs))
	}
	if got := string(msgs[3].Payload); !strings.Contains(got, "end_turn") {
		t.Fatalf("messageStop payload %s", got)
	}
}

// A flipped payload byte is caught.
func TestCorruptionDetected(t *testing.T) {
	fix := awsFixture(t)
	fix[30] ^= 0xff
	var d Decoder
	if _, _, err := d.Feed(fix); !errors.Is(err, ErrCRC) {
		t.Fatalf("got %v, want ErrCRC", err)
	}
}

// BenchmarkSigV4Resign: the cost of re-signing a rewritten 1 MiB Bedrock
// request (payload hash + signature), the work a request rewrite adds.
func BenchmarkSigV4Resign(b *testing.B) {
	body := bytes.Repeat([]byte("a"), 1<<20)
	signer := v4.NewSigner()
	creds := aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret"}
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		sum := sha256.Sum256(body)
		req, _ := http.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse-stream", bytes.NewReader(body))
		if err := signer.SignHTTP(context.Background(), creds, req, hex.EncodeToString(sum[:]), "bedrock", "us-east-1", time.Now()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReencodeFrame: decode + re-encode one ~1 KiB frame.
func BenchmarkReencodeFrame(b *testing.B) {
	var buf bytes.Buffer
	var h awses.Headers
	h.Set(":event-type", awses.StringValue("contentBlockDelta"))
	_ = awses.NewEncoder().Encode(&buf, awses.Message{Headers: h, Payload: bytes.Repeat([]byte("x"), 1024)})
	raw := buf.Bytes()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		var d Decoder
		fs, _, _ := d.Feed(raw)
		_ = Encode(fs[0])
	}
}
