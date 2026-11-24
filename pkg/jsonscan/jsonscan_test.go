package jsonscan

import (
	"errors"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

const body = `{"model":"claude-opus-5-5","stream":true,"messages":[{"role":"user","content":"hi","model":"inner"}],"meta":{"model":"nested"}}`

func TestTopLevelModel(t *testing.T) {
	got, err := Fields(strings.NewReader(body), 256, "model")
	if err != nil {
		t.Fatal(err)
	}
	if got["model"] != "claude-opus-5-5" || len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestNestedKeyIgnored(t *testing.T) {
	in := `{"messages":[{"model":"inner"}],"meta":{"model":"nested"}}`
	got, err := Fields(strings.NewReader(in), 256, "model")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("nested key returned: %v", got)
	}
}

func TestSeveralKeys(t *testing.T) {
	in := ` { "a" : "1" , "b" : 2 , "c" : "3" } `
	got, err := Fields(strings.NewReader(in), 256, "a", "b", "c")
	if err != nil {
		t.Fatal(err)
	}
	// b is a number, so it is not returned.
	if len(got) != 2 || got["a"] != "1" || got["c"] != "3" {
		t.Fatalf("got %v", got)
	}
}

func TestEscapedString(t *testing.T) {
	in := `{"model":"claude \"x\" \\ \/ \n\t 😀"}`
	got, err := Fields(strings.NewReader(in), 256, "model")
	if err != nil {
		t.Fatal(err)
	}
	if want := "claude \"x\" \\ / \n\t \U0001F600"; got["model"] != want {
		t.Fatalf("got %q, want %q", got["model"], want)
	}
}

func TestLastDuplicateWins(t *testing.T) {
	got, err := Fields(strings.NewReader(`{"model":"a","model":"b"}`), 256, "model")
	if err != nil {
		t.Fatal(err)
	}
	if got["model"] != "b" {
		t.Fatalf("got %v", got)
	}
}

// "" is a valid key. Asking for it must work, and other keys must not be
// taken for it.
func TestEmptyKey(t *testing.T) {
	for doc, want := range map[string]map[string]string{
		`{"":"a"}`:                      {"": "a"},
		`{"":"a","":"b"}`:               {"": "b"},
		`{"":"a","":1}`:                 {},
		`{"x":"y"}`:                     {},
		`{"":"a","model":"m","":"c"}`:   {"": "c", "model": "m"},
		`{"model":"m","":{"":"inner"}}`: {"model": "m"},
	} {
		got, err := Fields(strings.NewReader(doc), 256, "", "model")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", doc, got, want)
		}
	}
}

func TestStringValueThenOtherTypeClears(t *testing.T) {
	// The later duplicate is not a string, so no string value stands for the key.
	got, err := Fields(strings.NewReader(`{"model":"a","model":{"x":"y"}}`), 256, "model")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["model"]; ok {
		t.Fatalf("got %v", got)
	}
}

func TestEverySplitPoint(t *testing.T) {
	want, err := Fields(strings.NewReader(body), 256, "model")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Fields(iotest.OneByteReader(strings.NewReader(body)), 256, "model")
	if err != nil || got["model"] != want["model"] {
		t.Fatalf("one byte at a time: %v %v", got, err)
	}
	esc := `{"model":"claude😀","x":"\\"}`
	for i := 1; i < len(esc); i++ {
		r := io.MultiReader(strings.NewReader(esc[:i]), strings.NewReader(esc[i:]))
		got, err := Fields(r, 256, "model")
		if err != nil || got["model"] != "claude\U0001F600" {
			t.Fatalf("split at %d: %v %v", i, got, err)
		}
	}
}

func TestNotAnObject(t *testing.T) {
	for _, in := range []string{`[{"model":"m"}]`, `"model"`, `42`, ``, `   `} {
		got, err := Fields(strings.NewReader(in), 256, "model")
		if err != nil || len(got) != 0 {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
}

func TestTruncated(t *testing.T) {
	for _, in := range []string{`{"model":"m"`, `{"model":"m`, `{"model":`, `{"a":[1,2`, `{`} {
		_, err := Fields(strings.NewReader(in), 256, "model")
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%q: err = %v", in, err)
		}
	}
}

func TestTruncatedKeepsWhatWasRead(t *testing.T) {
	got, err := Fields(strings.NewReader(`{"model":"m","messages":[`), 256, "model")
	if !errors.Is(err, io.ErrUnexpectedEOF) || got["model"] != "m" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestValueOverMax(t *testing.T) {
	in := `{"model":"` + strings.Repeat("a", 300) + `","other":"ok"}`
	got, err := Fields(strings.NewReader(in), 256, "model", "other")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["model"]; ok {
		t.Fatal("over-long value returned")
	}
	if got["other"] != "ok" {
		t.Fatalf("got %v", got)
	}
}

func TestReadError(t *testing.T) {
	boom := errors.New("boom")
	_, err := Fields(io.MultiReader(strings.NewReader(`{"a":`), iotest.ErrReader(boom)), 256, "a")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

// bigBody yields {"image":"AAAA…","model":"m"} with an n-byte string, without
// ever holding it.
type bigBody struct {
	n     int
	stage int
	fill  []byte
}

func (b *bigBody) Read(p []byte) (int, error) {
	switch b.stage {
	case 0:
		b.stage = 1
		return copy(p, `{"image":"`), nil
	case 1:
		if b.n == 0 {
			b.stage = 2
			return copy(p, `","model":"m"}`), nil
		}
		n := min(len(p), b.n, len(b.fill))
		copy(p, b.fill[:n])
		b.n -= n
		return n, nil
	}
	return 0, io.EOF
}

func TestConstantMemory(t *testing.T) {
	fill := []byte(strings.Repeat("A", 64<<10))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, err := Fields(&bigBody{n: 30 << 20, fill: fill}, 256, "model")
	runtime.ReadMemStats(&after)
	if err != nil || got["model"] != "m" {
		t.Fatalf("%v %v", got, err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 1<<20 {
		t.Fatalf("allocated %d bytes scanning a 30 MiB body, want under 1 MiB", alloc)
	}
}
