package plugin

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// fourMethods has the four C6 methods and nothing else.
type fourMethods struct{}

func (fourMethods) Classify(string, string, io.Reader) (string, string, bool) { return "", "", false }
func (fourMethods) Evaluate(context.Context, Request) Verdict                 { return Verdict{} }
func (fourMethods) DenyResponse(string, Verdict) (int, http.Header, []byte) {
	return 0, nil, nil
}
func (fourMethods) StreamError(string, string) []byte { return nil }

var _ Evaluator = fourMethods{}

func TestNoneRegistered(t *testing.T) {
	reset()
	if Registered() != nil {
		t.Fatal("an evaluator is registered in a build that registered none")
	}
}

func TestRegisterAndRead(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(fourMethods{})
	if Registered() == nil {
		t.Fatal("Registered returned nil after Register")
	}
}

func TestRegisterTwicePanics(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(fourMethods{})
	defer func() {
		if recover() == nil {
			t.Fatal("a second Register did not panic")
		}
	}()
	Register(fourMethods{})
}

func TestRegisterNilPanics(t *testing.T) {
	reset()
	defer func() {
		if recover() == nil {
			t.Fatal("Register(nil) did not panic")
		}
		if Registered() != nil {
			t.Fatal("nil was registered")
		}
	}()
	Register(nil)
}
