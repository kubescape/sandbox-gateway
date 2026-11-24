package plugin

import "sync"

var (
	mu         sync.Mutex
	registered Evaluator
)

// Register installs the evaluator for this build. It panics on nil and on a
// second call. A build calls it from an init function of the package that
// implements the evaluator.
func Register(e Evaluator) {
	mu.Lock()
	defer mu.Unlock()
	if e == nil {
		panic("plugin: Register with a nil evaluator")
	}
	if registered != nil {
		panic("plugin: Register called twice")
	}
	registered = e
}

// Registered returns the evaluator, or nil when the build has none.
func Registered() Evaluator {
	mu.Lock()
	defer mu.Unlock()
	return registered
}

// reset clears the registry. Tests only.
func reset() {
	mu.Lock()
	registered = nil
	mu.Unlock()
}
