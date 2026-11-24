package extproc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Review: a result is accepted only if the call returned by the deadline.
// Here the call returns after its deadline and before anyone waits, the case
// where the order the scheduler wakes things in used to decide.
func TestLateResultRefused(t *testing.T) {
	c := newCalls(2)
	deadline := time.Now().Add(20 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	cl, err := begin(c, ctx, func(ctx context.Context) string {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond) // answers after the deadline
		return "allow"
	})
	if err != nil {
		t.Fatal(err)
	}
	<-cl.done // finished, late, before the wait
	if v, err := cl.waitUntil(deadline); !errors.Is(err, errTimeout) {
		t.Fatalf("late result accepted: %q, %v", v, err)
	}
	if n := c.stuck.Load(); n != 0 {
		t.Fatalf("stuck = %d: a call that has returned is not stuck", n)
	}

	// On time is accepted.
	cl, _ = begin(c, context.Background(), func(context.Context) string { return "allow" })
	if v, err := cl.waitUntil(time.Now().Add(time.Second)); err != nil || v != "allow" {
		t.Fatalf("on-time result: %q, %v", v, err)
	}
}
