// Package plugin is the seam between the processor framework and a rule
// evaluator.
//
// The framework parses streams, runs the watchdog and writes records. It does
// not decide anything. A build that wires in an Evaluator gets a Decision per
// inspected request; a build without one passes every request and records no
// decision.
//
// This is a first cut, sized to what the PoC code needs. The processor
// framework work replaces it with the full interface (workload identity, policy
// sections, provider-shaped deny responses).
package plugin

// Action is what the evaluator decided for one request.
type Action string

const (
	Allow     Action = "allow"
	WouldDeny Action = "would_deny" // audit twin of deny
	Deny      Action = "deny"       // enforce mode: blocked
	NoVerdict Action = "no_verdict" // the request could not be evaluated
)

// Decision is the outcome for one transaction. The framework copies it into
// the transaction record and the access log.
type Decision struct {
	RuleID   string   `json:"rule_id"`
	Action   Action   `json:"action"`
	Reason   string   `json:"reason,omitempty"`
	Model    string   `json:"model,omitempty"`
	Stream   bool     `json:"stream"`
	Tools    []string `json:"tools,omitempty"`
	Messages int      `json:"messages"`
	// ClassVersion names the policy document that decided this. Degraded means
	// that document was stale or missing: the decision is audit only and the
	// framework never blocks on it.
	ClassVersion   string `json:"class_version,omitempty"`
	Degraded       bool   `json:"degraded,omitempty"`
	DegradedReason string `json:"degraded_reason,omitempty"`
}

// Evaluator decides requests. Implementations must be safe for concurrent use.
type Evaluator interface {
	// Inspects reports whether requests to this HTTP path are evaluated. The
	// path may carry a query string.
	Inspects(path string) bool
	// NewScan starts the evaluation of one request.
	NewScan() Scan
}

// Scan evaluates one request body as it streams. It is used by one goroutine.
type Scan interface {
	// Feed takes the next body chunk. The framework forwards the chunk either
	// way, so Feed must not keep it.
	Feed(chunk []byte)
	// Decide is called once, after the last chunk.
	Decide() Decision
}
