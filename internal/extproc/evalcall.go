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
	given    bool // wait already returned: a later finish is a stuck call ending
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
			cl.finished, cl.v, cl.panicked = true, v, panicked
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
	var zero T
	timer := time.NewTimer(d)
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

// run makes one bounded call: begin, then wait d. f gets a context that ends
// at d, so an evaluator that honours its context gives its slot back at the
// budget; one that ignores it keeps the slot and counts as stuck.
func run[T any](c *calls, ctx context.Context, d time.Duration, f func(context.Context) T) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	cl, err := begin(c, ctx, func(ctx context.Context) T {
		defer cancel()
		return f(ctx)
	})
	if err != nil {
		cancel()
		var zero T
		return zero, err
	}
	return cl.wait(d)
}
