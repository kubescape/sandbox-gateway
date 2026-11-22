// Package lookup asks node-agent which workload owns a cgroup and which
// policy objects cover it, over a local unix socket:
//
//	GET /v1/workload?cgroup=<id>
//	200 {"namespace","pod","container","controller":{"kind","name"},
//	     "bindingId","policies":[{"uid","generation"}]}
//	404 when the cgroup is not bound
//
// The answer says who the workload is. It does not carry the rules.
//
// Answers are cached per cgroup, so a node-agent restart does not stop the
// processor: while the socket is down the last answer keeps being served,
// together with the time the socket stopped answering. The caller decides
// what that age means.
package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// DefaultSocket is where node-agent serves the lookup.
const DefaultSocket = "/run/kubescape-sandbox/lookup.sock"

// ErrNotBound means node-agent answered that the cgroup is not a bound pod.
var ErrNotBound = errors.New("lookup: cgroup is not bound")

// idleEntry is how long an unused cache entry is kept. Pods come and go; the
// cache must not grow with every cgroup the node has ever had.
const idleEntry = 10 * time.Minute

// PolicyRef names one policy object that covers the workload.
type PolicyRef struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}

// Workload is node-agent's answer.
type Workload struct {
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	Controller struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"controller"`
	BindingID uint32      `json:"bindingId"`
	Policies  []PolicyRef `json:"policies"`
}

// retryAfter is how long a cgroup's lookup is left alone after it failed.
// Without it every request would ask a socket that is not answering, and each
// would wait for the client timeout.
const retryAfter = time.Second

// entry is what the client knows about one cgroup.
type entry struct {
	w        Workload
	have     bool // w holds an answer
	fetched  time.Time
	lastUsed time.Time
	retryAt  time.Time // after a failed fetch: do not fetch again before this
	lastErr  error     // the failure that set retryAt
	inflight *call     // the fetch in progress, if any
}

// call is one fetch that several requests may be waiting for.
type call struct {
	done         chan struct{}
	w            Workload
	failingSince time.Time
	err          error
}

// Client looks workloads up and caches the answers. It is safe for concurrent
// use.
type Client struct {
	http    *http.Client
	refresh time.Duration
	now     func() time.Time

	mu           sync.Mutex
	cache        map[uint64]*entry
	failingSince time.Time // zero while the socket answers
}

// New returns a client for the unix socket at socket. A cached answer older
// than refresh is fetched again. now is the clock.
func New(socket string, refresh time.Duration, now func() time.Time) *Client {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}
	return &Client{
		http:    &http.Client{Transport: &http.Transport{DialContext: dial, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}, Timeout: 2 * time.Second},
		refresh: refresh,
		now:     now,
		cache:   map[uint64]*entry{},
	}
}

// Workload returns the workload that owns cgroupID.
//
// While the socket answers, failingSince is zero. When it does not, the
// cached answer is returned with failingSince set to the time of the first
// failed request since the socket last answered; with nothing cached the
// error is returned. ErrNotBound is an answer, not a failure: it removes the
// cached entry.
//
// At most one request per cgroup is in flight. While it is, a call for the
// same cgroup gets the cached answer at once, or waits for the result when
// nothing is cached. After a failure the cgroup is not asked about again for
// retryAfter.
func (c *Client) Workload(ctx context.Context, cgroupID uint64) (w Workload, failingSince time.Time, err error) {
	now := c.now()
	c.mu.Lock()
	e, ok := c.cache[cgroupID]
	if !ok {
		e = &entry{}
		c.cache[cgroupID] = e
	}
	e.lastUsed = now
	switch {
	case e.have && now.Sub(e.fetched) < c.refresh:
		defer c.mu.Unlock()
		return e.w, c.failingSince, nil
	case now.Before(e.retryAt):
		defer c.mu.Unlock()
		if e.have {
			return e.w, c.failingSince, nil
		}
		return Workload{}, c.failingSince, e.lastErr
	case e.inflight != nil && e.have:
		defer c.mu.Unlock()
		return e.w, c.failingSince, nil
	case e.inflight != nil:
		cl := e.inflight
		c.mu.Unlock()
		select {
		case <-cl.done:
			return cl.w, cl.failingSince, cl.err
		case <-ctx.Done():
			return Workload{}, time.Time{}, fmt.Errorf("lookup: %w", ctx.Err())
		}
	}
	cl := &call{done: make(chan struct{})}
	e.inflight = cl
	c.mu.Unlock()

	fresh, ferr := c.fetch(ctx, cgroupID)

	c.mu.Lock()
	defer c.mu.Unlock()
	defer close(cl.done)
	e.inflight = nil
	c.prune(now)
	switch {
	case ferr == nil:
		c.failingSince = time.Time{}
		*e = entry{w: fresh, have: true, fetched: now, lastUsed: now}
		c.cache[cgroupID] = e
		cl.w = fresh
	case errors.Is(ferr, ErrNotBound):
		c.failingSince = time.Time{}
		delete(c.cache, cgroupID)
		cl.err = ErrNotBound
	default:
		// A caller that went away says nothing about the socket, so it starts
		// no retry interval and does not mark the socket as failing.
		if ctx.Err() == nil {
			if c.failingSince.IsZero() {
				c.failingSince = now
			}
			e.retryAt, e.lastErr = now.Add(retryAfter), ferr
		}
		cl.failingSince = c.failingSince
		if e.have {
			cl.w = e.w
		} else {
			cl.err = ferr
		}
	}
	return cl.w, cl.failingSince, cl.err
}

// prune drops entries nothing has asked for in a while. Called with mu held.
func (c *Client) prune(now time.Time) {
	for id, e := range c.cache {
		if now.Sub(e.lastUsed) > idleEntry {
			delete(c.cache, id)
		}
	}
}

func (c *Client) fetch(ctx context.Context, cgroupID uint64) (Workload, error) {
	// The host part is ignored: the transport always dials the socket.
	url := "http://node-agent/v1/workload?cgroup=" + strconv.FormatUint(cgroupID, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Workload{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Workload{}, fmt.Errorf("lookup: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Workload{}, ErrNotBound
	default:
		return Workload{}, fmt.Errorf("lookup: status %d", resp.StatusCode)
	}
	var w Workload
	if err := json.NewDecoder(resp.Body).Decode(&w); err != nil {
		return Workload{}, fmt.Errorf("lookup: decode answer: %w", err)
	}
	return w, nil
}
