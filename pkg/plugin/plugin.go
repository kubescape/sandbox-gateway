// Package plugin is the seam between the processor framework and an
// evaluator (contract C6).
//
// The framework identifies the workload, streams the request body to the
// evaluator, enforces the verdict it returns and writes the records. It decides
// nothing itself. A build registers at most one Evaluator (see Register); a
// build with none passes every request and reports the evaluator as
// unavailable.
//
// The declarations below are the contract as written. Additions to this
// package must not change them.
package plugin

import (
	"context"
	"io"
	"net/http"

	"github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// Workload is the pod that sent a request.
type Workload struct {
	Namespace, Pod, Container, ControllerKind, ControllerName string
	BindingID                                                 uint32
	Posture                                                   string // allow | deny, from the bindings map
	Policies                                                  []PolicyRef
}

// PolicyRef names one policy object that covers the workload.
type PolicyRef struct {
	UID        string
	Generation int64
}

// PolicySection is the http section of one covering policy object, unmerged.
type PolicySection struct {
	Ref  PolicyRef
	Mode string // spec.mode
	HTTP v1alpha1.HTTPSection
}

// Request is what the evaluator decides on.
type Request struct {
	Workload           Workload
	Sections           []PolicySection
	Host, Method, Path string
	Headers            http.Header
	Model              string
	HasModel           bool
	Degraded           bool
}

// Verdict is the evaluator's decision for one request.
type Verdict struct {
	Action                        string // allow | deny
	Mode                          string // audit | enforce
	WouldDeny                     bool
	PolicyUID                     string
	PolicyRevision                int64
	Rule, Origin, Provider, Model string
}

// Evaluator decides requests. Implementations must be safe for concurrent use.
type Evaluator interface {
	// Classify fills provider and model from the host, the path and the request body.
	Classify(host, path string, body io.Reader) (provider, model string, hasModel bool)
	Evaluate(ctx context.Context, r Request) Verdict
	// DenyResponse returns the provider-shaped error for a blocked request, and the frame that ends a stalled or blocked stream.
	DenyResponse(provider string, v Verdict) (status int, headers http.Header, body []byte)
	StreamError(provider string, reason string) []byte
}

// Values of Verdict.Action and Verdict.Mode.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)
