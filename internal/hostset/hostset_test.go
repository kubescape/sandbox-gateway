package hostset

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPatternMatch(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "a.b.github.com", true},
		{"*.github.com", "github.com", false},
		{"*.github.com", "evilgithub.com", false},
		{"*.openai.azure.com", "myres.openai.azure.com", true},
		{"*.openai.azure.com", "openai.azure.com", false},
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com", true},
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.a.b.amazonaws.com", false},
		{"bedrock-runtime.*.amazonaws.com", "bedrock.us-east-1.amazonaws.com", false},
		{"*-aiplatform.googleapis.com", "us-central1-aiplatform.googleapis.com", true},
		{"*-aiplatform.googleapis.com", "aiplatform.googleapis.com", false},
		{"*-aiplatform.googleapis.com", "x.us-central1-aiplatform.googleapis.com", false},
	}
	for _, c := range cases {
		pt, err := parsePattern(c.pattern)
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		if got := pt.match(c.host); got != c.want {
			t.Errorf("%s vs %s: got %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestBadPatterns(t *testing.T) {
	for _, p := range []string{"", "*", "*.com", "com", "foo.*", "*.*.com", "a..com", "x.*"} {
		if _, err := parsePattern(p); err == nil {
			t.Errorf("%q: want error", p)
		}
	}
}

func TestObserveOnlyPatternMatches(t *testing.T) {
	s, err := New([]string{"api.anthropic.com"}, []string{"*.openai.azure.com"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if s.Contains("myres.openai.azure.com") {
		t.Fatal("pattern host must not be in the set before it is observed")
	}
	if s.Observe("example.com") || s.Observe("api.anthropic.com") {
		t.Fatal("non-matching or exact names must not change the set")
	}
	if !s.Observe("MyRes.openai.azure.com.") {
		t.Fatal("matching name should join")
	}
	if s.Observe("myres.openai.azure.com") {
		t.Fatal("second sighting should not change the set")
	}
	want := []string{"api.anthropic.com", "myres.openai.azure.com"}
	if got := s.Hosts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
}

func TestCapEvictsLeastRecentlySeen(t *testing.T) {
	s, _ := New([]string{"api.anthropic.com"}, []string{"*.flood.invalid"}, 3)
	for i := 0; i < 3; i++ {
		s.Observe(fmt.Sprintf("h%d.flood.invalid", i))
	}
	s.Observe("h0.flood.invalid") // refresh h0: h1 is now the oldest
	s.Observe("h3.flood.invalid")
	if s.Contains("h1.flood.invalid") || !s.Contains("h0.flood.invalid") || !s.Contains("h3.flood.invalid") {
		t.Fatalf("LRU order wrong: %v", s.Hosts())
	}
	for i := 4; i < 1000; i++ {
		s.Observe(fmt.Sprintf("h%d.flood.invalid", i))
	}
	if s.Learned() != 3 || len(s.Hosts()) != 4 || !s.Contains("api.anthropic.com") {
		t.Fatalf("cap broken: learned=%d hosts=%v", s.Learned(), s.Hosts())
	}
	if s.Evicted() != 997 {
		t.Fatalf("evicted = %d, want 997", s.Evicted())
	}
}

func TestExactMustBeExact(t *testing.T) {
	if _, err := New([]string{"*.github.com"}, nil, 0); err == nil {
		t.Fatal("pattern in the exact list must be rejected")
	}
}
