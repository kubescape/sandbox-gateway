package policysource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/kubescape/sandbox-gateway/pkg/plugin"
)

// Static is a policy source over a fixed set of objects read from a file. It
// is for test programs that run without an API server; it is synced from the
// start and never loses its source.
type Static struct {
	byUID map[string]cached
	refs  []plugin.PolicyRef
}

// LoadStatic reads policy objects, as YAML or JSON documents separated by
// "---", from path. Every object needs a metadata.uid.
func LoadStatic(path string) (*Static, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	s := &Static{byUID: map[string]cached{}}
	dec := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var u unstructured.Unstructured
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("policysource: %s: %w", path, err)
		}
		if len(u.Object) == 0 {
			continue
		}
		if u.GetUID() == "" {
			return nil, fmt.Errorf("policysource: %s: %s/%s has no metadata.uid", path, u.GetKind(), u.GetName())
		}
		c, ok := convert(&u)
		if !ok {
			return nil, fmt.Errorf("policysource: %s: %s/%s is not a policy object", path, u.GetKind(), u.GetName())
		}
		s.byUID[c.ref.UID] = c
		s.refs = append(s.refs, plugin.PolicyRef{UID: string(u.GetUID()), Generation: u.GetGeneration()})
	}
	return s, nil
}

// Refs names every object in the file, as a lookup would for a workload they
// all cover.
func (s *Static) Refs() []plugin.PolicyRef { return s.refs }

// Resolve is Source.Resolve over the file's objects.
func (s *Static) Resolve(refs []plugin.PolicyRef) ([]plugin.PolicySection, int, int) {
	return resolveWith(func(uid string) (cached, bool) { c, ok := s.byUID[uid]; return c, ok }, refs)
}

// LostSince is always zero.
func (s *Static) LostSince() time.Time { return time.Time{} }

// Synced is always true.
func (s *Static) Synced() bool { return true }

// Run waits for ctx to end.
func (s *Static) Run(ctx context.Context) { <-ctx.Done() }
