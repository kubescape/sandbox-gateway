package extproc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/sandbox-gateway/pkg/jsonscan"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

const fakeRuleID = "test.canned-verdict"

// fakeEval is a test evaluator. It returns a canned verdict, keeps what it was
// given, and has hooks that make each call stall or panic, so the tests cover
// the framework's side of the seam and no rule logic.
type fakeEval struct {
	mu                                        sync.Mutex
	verdict                                   plugin.Verdict
	fed                                       []byte
	reqs                                      []plugin.Request
	classifies, evaluates, denies, streamErrs int

	// Hooks, each run inside the call when set.
	classifyHook  func(body io.Reader) // replaces reading the body
	evaluateHook  func(ctx context.Context)
	denyHook      func()
	streamErrHook func()
}

func auditDeny() *fakeEval {
	return &fakeEval{verdict: plugin.Verdict{Action: plugin.ActionDeny, Mode: plugin.ModeAudit, WouldDeny: true, Rule: fakeRuleID}}
}

func enforceDeny() *fakeEval {
	return &fakeEval{verdict: plugin.Verdict{Action: plugin.ActionDeny, Mode: plugin.ModeEnforce, Rule: fakeRuleID}}
}

func allowAll() *fakeEval {
	return &fakeEval{verdict: plugin.Verdict{Action: plugin.ActionAllow, Mode: plugin.ModeEnforce, Rule: fakeRuleID}}
}

func (f *fakeEval) Classify(host, _ string, body io.Reader) (string, string, bool) {
	f.mu.Lock()
	f.classifies++
	hook := f.classifyHook
	f.mu.Unlock()
	if hook != nil {
		hook(body)
		return "anthropic", "", false
	}
	var buf bytes.Buffer
	fields, _ := jsonscan.Fields(io.TeeReader(body, &buf), 256, "model")
	f.mu.Lock()
	f.fed = append(f.fed, buf.Bytes()...)
	f.mu.Unlock()
	provider := "openai"
	if strings.Contains(host, "anthropic") {
		provider = "anthropic"
	}
	m, ok := fields["model"]
	return provider, m, ok
}

func (f *fakeEval) Evaluate(ctx context.Context, r plugin.Request) plugin.Verdict {
	f.mu.Lock()
	f.evaluates++
	f.reqs = append(f.reqs, r)
	hook, v := f.evaluateHook, f.verdict
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	return v
}

func (f *fakeEval) DenyResponse(provider string, v plugin.Verdict) (int, http.Header, []byte) {
	f.mu.Lock()
	f.denies++
	hook := f.denyHook
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Fake", provider)
	return 403, h, []byte(fakeDenyBody(v.Rule))
}

func (f *fakeEval) StreamError(provider, reason string) []byte {
	f.mu.Lock()
	f.streamErrs++
	hook := f.streamErrHook
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return []byte(fakeStreamError(provider, reason))
}

func fakeDenyBody(rule string) string {
	return `{"type":"error","error":{"type":"permission_error","message":"fake deny: ` + rule + `"}}`
}

func fakeStreamError(provider, reason string) string {
	return fmt.Sprintf("event: error\ndata: {\"provider\":%q,\"reason\":%q}\n\n", provider, reason)
}

func (f *fakeEval) set(fn func(f *fakeEval)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *fakeEval) counts() (classifies, evaluates, denies, streamErrs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.classifies, f.evaluates, f.denies, f.streamErrs
}

func (f *fakeEval) body() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.fed)
}

func (f *fakeEval) lastRequest() plugin.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

// release returns a channel that closes when the test ends. A hook that
// blocks on it stands for an evaluator call that never returns; the close
// lets its goroutine go when the test is over.
func release(t *testing.T) <-chan struct{} {
	ch := make(chan struct{})
	t.Cleanup(func() { close(ch) })
	return ch
}

// waitIdle waits until the server runs no goroutine for any request: no
// evaluator call and no body write. stuck calls are allowed to remain.
func waitIdle(t *testing.T, s *Server, stuck int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		live, feeders := s.calls.live.Load(), s.feeders.Load()
		if live == stuck && feeders == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still running: %d evaluator calls (want %d stuck), %d body writes", live, stuck, feeders)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
