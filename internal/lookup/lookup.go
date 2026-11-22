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

type entry struct {
	w        Workload
	fetched  time.Time
	lastUsed time.Time
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
func (c *Client) Workload(ctx context.Context, cgroupID uint64) (w Workload, failingSince time.Time, err error) {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.cache[cgroupID]; ok && now.Sub(e.fetched) < c.refresh {
		e.lastUsed = now
		w, failingSince = e.w, c.failingSince
		c.mu.Unlock()
		return w, failingSince, nil
	}
	c.mu.Unlock()

	fresh, ferr := c.fetch(ctx, cgroupID)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	switch {
	case ferr == nil:
		c.failingSince = time.Time{}
		c.cache[cgroupID] = &entry{w: fresh, fetched: now, lastUsed: now}
		return fresh, time.Time{}, nil
	case errors.Is(ferr, ErrNotBound):
		c.failingSince = time.Time{}
		delete(c.cache, cgroupID)
		return Workload{}, time.Time{}, ErrNotBound
	}
	if c.failingSince.IsZero() {
		c.failingSince = now
	}
	if e, ok := c.cache[cgroupID]; ok {
		e.lastUsed = now
		return e.w, c.failingSince, nil
	}
	return Workload{}, c.failingSince, ferr
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
