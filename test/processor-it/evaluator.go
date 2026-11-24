package main

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/kubescape/sandbox-gateway/pkg/jsonscan"
	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// deniedModel is the model the test evaluator denies.
const deniedModel = "denied-model"

// testEvaluator denies a request for deniedModel, in the mode it was given,
// and allows the rest. It has no rules beyond that: it is there so the
// integration stack runs the evaluator path end to end.
type testEvaluator struct{ mode string }

func (testEvaluator) Classify(host, _ string, body io.Reader) (string, string, bool) {
	provider := "openai"
	if strings.Contains(host, "anthropic") {
		provider = "anthropic"
	}
	fields, _ := jsonscan.Fields(body, 256, "model")
	m, ok := fields["model"]
	return provider, m, ok
}

func (e testEvaluator) Evaluate(_ context.Context, r plugin.Request) plugin.Verdict {
	if r.Model != deniedModel {
		return plugin.Verdict{Action: plugin.ActionAllow, Mode: e.mode, Rule: "it.allow", Model: r.Model}
	}
	return plugin.Verdict{Action: plugin.ActionDeny, Mode: e.mode, WouldDeny: e.mode == plugin.ModeAudit,
		Rule: "it.denied-model", Model: r.Model}
}

func (testEvaluator) DenyResponse(string, plugin.Verdict) (int, http.Header, []byte) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return http.StatusForbidden, h,
		[]byte(`{"type":"error","error":{"type":"permission_error","message":"denied by the integration test evaluator"}}`)
}

func (testEvaluator) StreamError(_, reason string) []byte {
	return []byte(`event: error` + "\n" + `data: {"type":"error","error":{"type":"api_error","message":"gateway: ` + reason + `"}}` + "\n\n")
}
