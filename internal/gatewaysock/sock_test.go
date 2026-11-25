package gatewaysock

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSightings(t *testing.T) {
	var seen []string
	kicks := 0
	h := &Handler{
		Observe: func(n string) bool { seen = append(seen, n); return n == "myres.openai.azure.com" },
		Changed: func() { kicks++ },
	}
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()

	post := func(body string) (int, string) {
		resp, err := http.Post(srv.URL+"/v1/sightings", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b := make([]byte, 256)
		n, _ := resp.Body.Read(b)
		return resp.StatusCode, string(b[:n])
	}

	code, body := post(`{"name":"myres.openai.azure.com","addresses":["20.0.0.1"],"bindingIds":[7]}`)
	if code != 200 || !strings.Contains(body, `"changed":true`) {
		t.Fatalf("%d %s", code, body)
	}
	code, body = post(`{"name":"other.example.com","addresses":[],"bindingIds":[]}`)
	if code != 200 || !strings.Contains(body, `"changed":false`) {
		t.Fatalf("%d %s", code, body)
	}
	if len(seen) != 2 || kicks != 2 || h.Sightings.Load() != 2 || h.Learned.Load() != 1 {
		t.Fatalf("seen=%v kicks=%d sightings=%d learned=%d", seen, kicks, h.Sightings.Load(), h.Learned.Load())
	}

	for _, bad := range []string{``, `{}`, `{"name":""}`, `not json`} {
		if code, _ := post(bad); code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", bad, code)
		}
	}
	if code, _ := post(`{"name":"` + strings.Repeat("a", maxBody) + `"}`); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status %d", code)
	}
	resp, err := http.Get(srv.URL + "/v1/sightings")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d", resp.StatusCode)
	}
	if len(seen) != 2 {
		t.Fatalf("a refused request must not reach the set: %v", seen)
	}
}

func TestCerts(t *testing.T) {
	until := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)
	state := Certs{CanDecrypt: true, DecryptValidUntil: &until, RootFingerprint: "ab12"}
	h := &Handler{Certs: func() Certs { return state }}
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()
	get := func() string {
		resp, err := http.Get(srv.URL + "/healthz/certs")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		b := make([]byte, 512)
		n, _ := resp.Body.Read(b)
		return strings.TrimSpace(string(b[:n]))
	}
	if got, want := get(), `{"canDecrypt":true,"decryptValidUntil":"2026-11-24T15:00:00Z","rootFingerprint":"ab12"}`; got != want {
		t.Fatalf("body = %s\nwant   %s", got, want)
	}
	// No intermediate: still 200, and the body says the node cannot decrypt.
	state = Certs{}
	if got, want := get(), `{"canDecrypt":false,"rootFingerprint":""}`; got != want {
		t.Fatalf("body = %s\nwant   %s", got, want)
	}
	resp, err := http.Post(srv.URL+"/healthz/certs", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status %d", resp.StatusCode)
	}
}
