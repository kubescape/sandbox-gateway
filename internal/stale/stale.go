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
	"sync"
	"time"
)

// Tracker keeps, per cgroup, when a referenced policy first failed to
// resolve. An entry stays while its workload does, however long it is idle,
// so a workload that comes back after a quiet spell is still degraded if its
// policy never resolved. It leaves when its policy resolves or when the
// workload is gone (Forget). It is safe for concurrent use.
type Tracker struct {
	limit time.Duration
	now   func() time.Time
	mu    sync.Mutex
	since map[uint64]entry
}

type entry struct{ since, seen time.Time }

// maxEntries bounds the map against cgroups nobody forgets: past it, the
// entry seen least recently goes.
const maxEntries = 1 << 16

// New returns a tracker that degrades a workload stale for limit or more.
func New(limit time.Duration, now func() time.Time) *Tracker {
	return &Tracker{limit: limit, now: now, since: map[uint64]entry{}}
}

// Observe records what one request saw for a workload and reports whether its
// decision is degraded. lookupFailingSince and informerLostSince are zero while
// those sources answer; unresolved is whether a referenced policy is missing
// from the cache or cached at another generation.
func (t *Tracker) Observe(cgroupID uint64, lookupFailingSince, informerLostSince time.Time, unresolved bool) (degraded bool) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	e, had := t.since[cgroupID]
	switch {
	case unresolved && !had:
		t.evictIfFull()
		t.since[cgroupID] = entry{since: now, seen: now}
		e = t.since[cgroupID]
	case unresolved:
		e.seen = now
		t.since[cgroupID] = e
	default:
		delete(t.since, cgroupID)
		e = entry{}
	}
	since := earliest(lookupFailingSince, informerLostSince, e.since)
	return !since.IsZero() && now.Sub(since) >= t.limit
}

// Forget drops a cgroup whose workload is gone: unbound, or no longer in the
// kernel tables.
func (t *Tracker) Forget(cgroupID uint64) {
	t.mu.Lock()
	delete(t.since, cgroupID)
	t.mu.Unlock()
}

// evictIfFull makes room for one entry. Called with mu held.
func (t *Tracker) evictIfFull() {
	if len(t.since) < maxEntries {
		return
	}
	var oldest uint64
	var at time.Time
	for id, e := range t.since {
		if at.IsZero() || e.seen.Before(at) {
			oldest, at = id, e.seen
		}
	}
	delete(t.since, oldest)
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
