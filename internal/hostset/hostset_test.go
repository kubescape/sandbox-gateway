package hostset

import (
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

func TestMatch(t *testing.T) {
	for _, c := range []struct {
		pattern, host string
		want          bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"bedrock-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com", true},
		{"bedrock-runtime.*.amazonaws.com", "bedrock.us-east-1.amazonaws.com", false},
		{"*.example.com", "API.Example.com.", true},
		{"*", "anything.com", false},
	} {
		if got := Match(c.pattern, c.host); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}
