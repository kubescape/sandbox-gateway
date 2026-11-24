package extproc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Why a call into the evaluator gave no answer.
var (
	errNoSlot  = errors.New("no free evaluator slot")
	errTimeout = errors.New("evaluator call over its budget")
	errPanic   = errors.New("evaluator call panicked")
)

// calls bounds the calls into the evaluator (decision 10). Each call runs in
// its own goroutine and holds a slot until it returns. A call that runs past
// its deadline keeps its goroutine and its slot, because Go cannot stop a
// function that ignores its context; the slots cap how many such calls pile
// up. A call that finds no free slot is not made.
type calls struct {
	slots chan struct{}
	stuck atomic.Int64 // calls still running past their deadline
	live  atomic.Int64 // calls running, stuck or not
}

func newCalls(max int) *calls {
	if max <= 0 {
		max = DefaultMaxEvaluatorCalls
	}
	return &calls{slots: make(chan struct{}, max)}
}

// call is one call into the evaluator.
type call[T any] struct {
	c        *calls
	done     chan struct{}
	mu       sync.Mutex
	finished bool
	at       time.Time // when the call returned
	given    bool      // counted as stuck: its finish decrements the count
	v        T
	panicked bool
}

// begin starts f in a goroutine, with ctx, if a slot is free.
func begin[T any](c *calls, ctx context.Context, f func(context.Context) T) (*call[T], error) {
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, errNoSlot
	}
	cl := &call[T]{c: c, done: make(chan struct{})}
	c.live.Add(1)
	go func() {
		var v T
		panicked := true
		defer func() {
			_ = recover()
			cl.mu.Lock()
			cl.finished, cl.at, cl.v, cl.panicked = true, time.Now(), v, panicked
			if cl.given {
				c.stuck.Add(-1)
			}
			cl.mu.Unlock()
			// The slot is free before the waiter wakes, so a caller that
			// saw this call end can make the next one.
			<-c.slots
			c.live.Add(-1)
			close(cl.done)
		}()
		v = f(ctx)
		panicked = false
	}()
	return cl, nil
}

// wait returns the call's result, or errTimeout when it has not returned
// within d. After a timeout the call counts as stuck until it returns.
func (cl *call[T]) wait(d time.Duration) (T, error) {
	return cl.waitUntil(time.Now().Add(d))
}

// waitUntil returns the call's result if the call returned by deadline, and
// errTimeout otherwise. A result that comes after the deadline is refused
// even when the waiter sees it, so which side of the deadline a result falls
// on decides the outcome, not the order the scheduler wakes things in.
func (cl *call[T]) waitUntil(deadline time.Time) (T, error) {
	var zero T
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-cl.done:
	case <-timer.C:
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	switch {
	case !cl.finished:
		cl.markStuck()
		return zero, errTimeout
	case cl.at.After(deadline):
		return zero, errTimeout // late: refused, though no longer running
	case cl.panicked:
		return zero, errPanic
	}
	return cl.v, nil
}

// abandon gives up on a call that the caller will not wait for: if it is
// still running, it counts as stuck until it returns.
func (cl *call[T]) abandon() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if !cl.finished {
		cl.markStuck()
	}
}

// markStuck counts the call as stuck, once. Called with mu held.
func (cl *call[T]) markStuck() {
	if !cl.given {
		cl.given = true
		cl.c.stuck.Add(1)
	}
}

// run makes one bounded call: begin, then wait until d has passed. f gets a
// context that ends at the same deadline the result must arrive by, so an
// evaluator that honours its context gives its slot back at the budget, and
// one that answers after it is refused. One that ignores its context keeps
// the slot and counts as stuck.
func run[T any](c *calls, ctx context.Context, d time.Duration, f func(context.Context) T) (T, error) {
	deadline := time.Now().Add(d)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	cl, err := begin(c, ctx, func(ctx context.Context) T {
		defer cancel()
		return f(ctx)
	})
	if err != nil {
		cancel()
		var zero T
		return zero, err
	}
	return cl.waitUntil(deadline)
}
