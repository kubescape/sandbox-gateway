package nodeview

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// Static is a Source over objects read from a file, for test programs that
// run without an API server. It is synced from the start and never changes.
type Static struct {
	snap    Snapshot
	changed chan struct{}
}

// LoadStatic reads Pod, Namespace, SandboxPolicy and ClusterSandboxPolicy
// objects, as YAML or JSON documents separated by "---", from path, and
// builds the view of the node named node. An empty node takes every pod.
func LoadStatic(path, node string) (*Static, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var pods, spaces, policies []*unstructured.Unstructured
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		u := &unstructured.Unstructured{}
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("nodeview: %s: %w", path, err)
		}
		if len(u.Object) == 0 {
			continue
		}
		switch u.GetKind() {
		case "Pod":
			pods = append(pods, u)
		case "Namespace":
			spaces = append(spaces, u)
		case "SandboxPolicy", "ClusterSandboxPolicy":
			policies = append(policies, u)
		default:
			return nil, fmt.Errorf("nodeview: %s: kind %q is not one the view reads", path, u.GetKind())
		}
	}
	return &Static{snap: build(node, pods, spaces, policies), changed: make(chan struct{})}, nil
}

// Snapshot implements Source.
func (s *Static) Snapshot() Snapshot { return s.snap }

// Synced is always true.
func (s *Static) Synced() bool { return true }

// Changed never fires.
func (s *Static) Changed() <-chan struct{} { return s.changed }

// Run waits for ctx to end.
func (s *Static) Run(ctx context.Context) { <-ctx.Done() }
