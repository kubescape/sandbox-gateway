// Package stale decides when a workload's policy is too old to trust: when
// the decision for it is degraded.
//
// Three things make a workload's policy stale: node-agent's lookup is serving
// it from a cache because the socket does not answer, the policy informers
// have lost the API server, or a policy the workload references is not in
// the informer cache. A workload is stale since the earliest of the three, and
// its decisions are degraded once that is limit or more ago.
package stale

import (
	"context"
	"sync"
	"time"
)

// Tracker keeps, per cgroup, when a referenced policy first failed to
// resolve. An entry stays while its workload does, however long it is idle,
// so a workload that comes back after a quiet spell is still degraded if its
// policy never resolved. It leaves when its policy resolves or when the
// workload is confirmed gone: a request finds it unbound (Forget), or a sweep
// of the kernel bindings table does not find it (Sweep). Nothing else removes
// an entry, so no live workload's clock restarts. It is safe for concurrent
// use.
type Tracker struct {
	limit time.Duration
	now   func() time.Time
	mu    sync.Mutex
	since map[uint64]entry
	// seq numbers observations, so a sweep can tell that an entry was
	// observed again after it read the bindings table.
	seq uint64
	// lostTrack is set once a workload could not be given any entry. From
	// then on every workload newly admitted may be that one, so each starts
	// with an unknown age. It lasts until the processor restarts.
	lostTrack bool
}

// entry is one workload whose policy does not resolve. unknown is set when
// the tracker was full as it arrived: its first miss was not recorded, so its
// decisions are degraded from the start.
type entry struct {
	since   time.Time
	unknown bool
	seq     uint64
}

// maxEntries is how many workloads the tracker times. Past it no entry is
// dropped to make room: a workload newly unresolved gets an entry of unknown
// age, up to as many again (maxUnknown), and is degraded at once.
const (
	maxEntries = 1 << 16
	maxUnknown = maxEntries
)

// New returns a tracker that degrades a workload stale for limit or more.
func New(limit time.Duration, now func() time.Time) *Tracker {
	return &Tracker{limit: limit, now: now, since: map[uint64]entry{}}
}

// Observe records what one request saw for a workload and reports whether its
// decision is degraded. lookupFailingSince and informerLostSince are zero while
// those sources answer; unresolved is whether a referenced policy is missing
// from the cache or cached at another generation.
//
// With the tracker full, a workload newly unresolved gets an entry of unknown
// age, and its decisions are degraded at once: it is not given a fresh grace
// period, now or once a slot opens, and the workloads already tracked keep
// theirs.
func (t *Tracker) Observe(cgroupID uint64, lookupFailingSince, informerLostSince time.Time, unresolved bool) (degraded bool) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	e, had := t.since[cgroupID]
	if !unresolved {
		delete(t.since, cgroupID)
		since := earliest(lookupFailingSince, informerLostSince)
		return !since.IsZero() && now.Sub(since) >= t.limit
	}
	if !had {
		switch n := len(t.since); {
		case n >= maxEntries+maxUnknown:
			t.lostTrack = true
			return true
		case n >= maxEntries || t.lostTrack:
			e = entry{unknown: true}
		default:
			e = entry{since: now}
		}
	}
	t.seq++
	e.seq = t.seq
	t.since[cgroupID] = e
	if e.unknown {
		return true
	}
	since := earliest(lookupFailingSince, informerLostSince, e.since)
	return now.Sub(since) >= t.limit
}

// Forget drops a cgroup whose workload is gone: unbound, or no longer in the
// kernel tables.
func (t *Tracker) Forget(cgroupID uint64) {
	t.mu.Lock()
	delete(t.since, cgroupID)
	t.mu.Unlock()
}

// Bound reports whether a cgroup is still in the kernel bindings table.
type Bound func(cgroupID uint64) (bool, error)

// Sweep drops every entry whose cgroup bound confirms is gone. A read that
// fails keeps the entry. The table is read without the lock held, so requests
// are not held up behind it; an entry observed again after its read is kept,
// since that request saw the workload bound later than the sweep did.
func (t *Tracker) Sweep(bound Bound) (removed int) {
	type seen struct{ id, seq uint64 }
	t.mu.Lock()
	snap := make([]seen, 0, len(t.since))
	for id, e := range t.since {
		snap = append(snap, seen{id, e.seq})
	}
	t.mu.Unlock()
	for _, s := range snap {
		if ok, err := bound(s.id); err != nil || ok {
			continue
		}
		t.mu.Lock()
		if e, had := t.since[s.id]; had && e.seq == s.seq {
			delete(t.since, s.id)
			removed++
		}
		t.mu.Unlock()
	}
	return removed
}

// Run sweeps every interval until ctx ends. Requests only forget a workload
// they see unbound; this reclaims the ones no request sees again.
func (t *Tracker) Run(ctx context.Context, every time.Duration, bound Bound) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.Sweep(bound)
		}
	}
}

func earliest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if !t.IsZero() && (out.IsZero() || t.Before(out)) {
			out = t
		}
	}
	return out
}
