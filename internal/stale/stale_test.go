package stale

import (
	"errors"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClock() *clock { return &clock{t: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)} }

func TestFreshIsNotDegraded(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	if tr.Observe(1, time.Time{}, time.Time{}, false) {
		t.Fatal("fresh workload degraded")
	}
}

func TestDegradedAfterFiveMinutes(t *testing.T) {
	for _, cause := range []string{"lookup", "informer", "unresolved"} {
		t.Run(cause, func(t *testing.T) {
			clk := newClock()
			tr := New(5*time.Minute, clk.now)
			start := clk.t
			observe := func() bool {
				switch cause {
				case "lookup":
					return tr.Observe(1, start, time.Time{}, false)
				case "informer":
					return tr.Observe(1, time.Time{}, start, false)
				}
				return tr.Observe(1, time.Time{}, time.Time{}, true)
			}
			if observe() {
				t.Fatal("degraded at once")
			}
			clk.t = start.Add(5*time.Minute - time.Second)
			if observe() {
				t.Fatal("degraded at 4m59s")
			}
			clk.t = start.Add(5 * time.Minute)
			if !observe() {
				t.Fatal("not degraded at 5m")
			}
		})
	}
}

func TestUnresolvedClockStartsAtFirstMiss(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	clk.t = clk.t.Add(time.Hour) // a long healthy stretch first
	tr.Observe(1, time.Time{}, time.Time{}, false)
	first := clk.t
	tr.Observe(1, time.Time{}, time.Time{}, true)
	clk.t = first.Add(3 * time.Minute)
	tr.Observe(1, time.Time{}, time.Time{}, true) // a later miss does not restart the clock
	clk.t = first.Add(5 * time.Minute)
	if !tr.Observe(1, time.Time{}, time.Time{}, true) {
		t.Fatal("the clock did not start at the first miss")
	}
	// Another cgroup has its own clock.
	if tr.Observe(2, time.Time{}, time.Time{}, true) {
		t.Fatal("cgroup 2 degraded by cgroup 1's clock")
	}
}

func TestRecoveryResets(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	tr.Observe(1, time.Time{}, time.Time{}, true)
	clk.t = clk.t.Add(6 * time.Minute)
	if !tr.Observe(1, time.Time{}, time.Time{}, true) {
		t.Fatal("not degraded")
	}
	if tr.Observe(1, time.Time{}, time.Time{}, false) {
		t.Fatal("still degraded once everything resolves")
	}
	if tr.Observe(1, time.Time{}, time.Time{}, true) {
		t.Fatal("a new miss reused the old clock")
	}
}

func TestEarliestCauseWins(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	lost := clk.t
	clk.t = clk.t.Add(4 * time.Minute)
	tr.Observe(1, time.Time{}, lost, true) // the miss is new, the informer outage is not
	clk.t = lost.Add(5 * time.Minute)
	if !tr.Observe(1, time.Time{}, lost, true) {
		t.Fatal("the informer outage, the earliest cause, did not decide")
	}
}

// Review: an idle workload keeps its unresolved clock; it does not restart
// fresh after a quiet spell.
func TestIdleWorkloadKeepsItsClock(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	tr.Observe(1, time.Time{}, time.Time{}, true)
	clk.t = clk.t.Add(24 * time.Hour) // no request for a day
	if !tr.Observe(1, time.Time{}, time.Time{}, true) {
		t.Fatal("the idle workload came back fresh")
	}
}

func TestForgetDropsTheWorkload(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	tr.Observe(1, time.Time{}, time.Time{}, true)
	clk.t = clk.t.Add(time.Hour)
	tr.Forget(1)
	if tr.Observe(1, time.Time{}, time.Time{}, true) {
		t.Fatal("a forgotten workload kept its clock")
	}
}

// Review: at capacity, a live workload whose policy stays unresolved keeps
// its clock, and one that cannot be tracked is degraded rather than given a
// fresh grace period.
func TestLiveUnresolvedWorkloadKeepsItsClockAtCapacity(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	tr.Observe(1, time.Time{}, time.Time{}, true) // the live workload, first miss now
	clk.t = clk.t.Add(time.Minute)
	for id := uint64(2); id <= maxEntries; id++ { // fill the tracker
		tr.Observe(id, time.Time{}, time.Time{}, true)
	}
	if !tr.Observe(maxEntries+1, time.Time{}, time.Time{}, true) {
		t.Fatal("a workload the full tracker cannot hold was not degraded")
	}
	clk.t = clk.t.Add(4 * time.Minute) // five minutes after workload 1's first miss
	if !tr.Observe(1, time.Time{}, time.Time{}, true) {
		t.Fatal("eviction pressure restarted a live workload's clock")
	}
}

func TestSweepDropsOnlyConfirmedGoneWorkloads(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	for id := uint64(1); id <= maxEntries; id++ {
		tr.Observe(id, time.Time{}, time.Time{}, true)
	}
	gone := map[uint64]bool{7: true, 8: true}
	removed := tr.Sweep(func(id uint64) (bool, error) {
		if id == 9 {
			return false, errors.New("read failed") // unknown: kept
		}
		return !gone[id], nil
	})
	if removed != 2 {
		t.Fatalf("removed = %d", removed)
	}
	clk.t = clk.t.Add(time.Minute)
	if tr.Observe(maxEntries+1, time.Time{}, time.Time{}, true) {
		t.Fatal("a new workload was degraded after a sweep made room")
	}
	clk.t = clk.t.Add(4 * time.Minute)
	if !tr.Observe(9, time.Time{}, time.Time{}, true) {
		t.Fatal("a workload whose bindings read failed lost its clock")
	}
	if tr.Observe(7, time.Time{}, time.Time{}, true) {
		t.Fatal("a swept workload kept its old clock")
	}
}

func fill(tr *Tracker, from, n uint64) {
	for id := from; id < from+n; id++ {
		tr.Observe(id, time.Time{}, time.Time{}, true)
	}
}

// Review: a workload the full tracker turned away stays degraded once a
// sweep makes room, rather than getting a fresh clock.
func TestOverflowWorkloadStaysDegradedAfterRoomOpens(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	fill(tr, 1, maxEntries)
	const late = maxEntries + 1
	if !tr.Observe(late, time.Time{}, time.Time{}, true) {
		t.Fatal("overflow workload not degraded")
	}
	if n := tr.Sweep(func(id uint64) (bool, error) { return id > 10, nil }); n != 10 {
		t.Fatalf("swept %d", n)
	}
	if !tr.Observe(late, time.Time{}, time.Time{}, true) {
		t.Fatal("the overflow workload got a fresh grace period once a slot opened")
	}
	if tr.Observe(late+1, time.Time{}, time.Time{}, true) {
		t.Fatal("a workload first seen after the sweep was degraded")
	}
}

// Past the unknown-age allowance the tracker can no longer tell which
// workload it dropped, so every workload admitted afterwards is degraded.
func TestLostTrackDegradesLaterAdmissions(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	fill(tr, 1, maxEntries+maxUnknown)
	const dropped = maxEntries + maxUnknown + 1
	if !tr.Observe(dropped, time.Time{}, time.Time{}, true) {
		t.Fatal("a workload with no entry was not degraded")
	}
	tr.Sweep(func(uint64) (bool, error) { return false, nil }) // everything else gone
	if !tr.Observe(dropped, time.Time{}, time.Time{}, true) {
		t.Fatal("the dropped workload got a fresh grace period")
	}
	if !tr.Observe(dropped+1, time.Time{}, time.Time{}, true) {
		t.Fatal("a later admission was not degraded after the tracker lost track")
	}
}

// Review: a request that observes a workload while the sweep reads its
// binding keeps the entry, and its clock.
func TestSweepKeepsEntryObservedDuringRead(t *testing.T) {
	clk := newClock()
	tr := New(5*time.Minute, clk.now)
	tr.Observe(5, time.Time{}, time.Time{}, true)
	clk.t = clk.t.Add(time.Minute)
	removed := tr.Sweep(func(id uint64) (bool, error) {
		// The binding was gone when read; a request then saw it restored.
		tr.Observe(id, time.Time{}, time.Time{}, true)
		return false, nil
	})
	if removed != 0 {
		t.Fatal("the sweep deleted an entry observed after its read")
	}
	clk.t = clk.t.Add(4 * time.Minute)
	if !tr.Observe(5, time.Time{}, time.Time{}, true) {
		t.Fatal("the workload lost its clock")
	}
}
