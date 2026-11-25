package hostset

import (
	"encoding/json"
	"os"
	"testing"
)

func TestWidthVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/host_pattern_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Pattern string `json:"pattern"`
			OK      bool   `json:"ok"`
			Why     string `json:"why"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 20 {
		t.Fatalf("only %d vectors read", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		err := CheckWidth(v.Pattern)
		if (err == nil) != v.OK {
			t.Errorf("%q: got error %v, want ok=%v (%s)", v.Pattern, err, v.OK, v.Why)
		}
	}
}

// Every wildcard pattern the width rule accepts must also be one the matcher
// can parse, or an accepted pattern would silently learn nothing.
func TestAcceptedWildcardsParse(t *testing.T) {
	for _, p := range []string{
		"*.openai.azure.com", "bedrock-runtime.*.amazonaws.com", "bedrock-runtime.eu-*.amazonaws.com",
		"*-aiplatform.googleapis.com", "eu-*-aiplatform.googleapis.com", "*.foo.co.uk",
	} {
		if err := CheckWidth(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
		if _, err := parsePattern(p); err != nil {
			t.Errorf("%q passes the width rule but does not parse: %v", p, err)
		}
	}
}
