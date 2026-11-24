// Command processor is the gateway's Envoy external processor (ext_proc). It
// attributes each request to a pod from the kernel connection table and
// node-agent's workload lookup, parses AI provider traffic and records it.
// This build registers no evaluator, so it passes every request and reports
// the evaluator as unavailable. A build with an evaluator is the same program
// with the evaluator imported (see pkg/processor).
package main

import "github.com/kubescape/sandbox-gateway/pkg/processor"

func main() { processor.Main() }
