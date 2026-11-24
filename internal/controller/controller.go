// Package controller is the node controller's reconcile loop. It turns the
// node view, the DNS sightings and the certificate authority into the
// listener Envoy runs.
package controller

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"

	"github.com/kubescape/sandbox-gateway/internal/ca"
	"github.com/kubescape/sandbox-gateway/internal/hostset"
	"github.com/kubescape/sandbox-gateway/internal/nodeview"
	"github.com/kubescape/sandbox-gateway/internal/xds"
)

// Listeners is where the built listeners go. *xds.LDS satisfies it.
type Listeners interface {
	Set(listeners ...*listenerv3.Listener) (changed bool, err error)
	Version() (current, acked, rejected, reason string)
}

// Activity knows which names have open connections, from Envoy's stats.
//
// When Envoy cannot be asked, every name counts as busy: a chain is never
// removed on a guess.
type Activity struct {
	// Stats reads Envoy's stats matching a filter. *envoyadmin.Client.Stats
	// satisfies it.
	Stats func(ctx context.Context, filter string) (map[string]int64, error)

	mu     sync.Mutex
	active map[string]int64
	known  bool
}

// activeFilter selects the open-connection gauge of every decrypt chain.
const activeFilter = `^http\.egress_.*\.downstream_cx_active$`

// Refresh reads the gauges. After a failed read every name is busy until a
// read succeeds.
func (a *Activity) Refresh(ctx context.Context) error {
	stats, err := a.Stats(ctx, activeFilter)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.known = false
		return err
	}
	a.active, a.known = stats, true
	return nil
}

// Busy reports whether name has open connections, as of the last Refresh.
func (a *Activity) Busy(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.known {
		return true
	}
	return a.active["http."+xds.StatPrefix(name)+".downstream_cx_active"] > 0
}

// Controller owns the loop. Set every exported field before Run.
type Controller struct {
	View      nodeview.Source
	Set       *hostset.NodeSet
	Authority *ca.Authority
	Listeners Listeners
	// Activity must be the source of the set's busy callback.
	Activity *Activity
	// KickSecrets pushes re-minted leaves at once. *sds.Server.Kick.
	KickSecrets func()
	Config      xds.Config
	Log         *slog.Logger
	// Every is how often the loop runs with nothing to react to, to sweep
	// names that went idle. Default 5s.
	Every time.Duration
	// Settle is how long the loop waits after a change for more of them.
	// Default 100ms.
	Settle time.Duration

	kickOnce sync.Once
	kick     chan struct{}

	// Reconciles counts completed runs; Errors the ones that failed.
	Reconciles, Errors atomic.Int64
}

func (c *Controller) kickChan() chan struct{} {
	c.kickOnce.Do(func() { c.kick = make(chan struct{}, 1) })
	return c.kick
}

// Kick asks for a reconcile soon. It never blocks.
func (c *Controller) Kick() {
	select {
	case c.kickChan() <- struct{}{}:
	default:
	}
}

// Run reconciles until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	every, settle := c.Every, c.Settle
	if every <= 0 {
		every = 5 * time.Second
	}
	if settle <= 0 {
		settle = 100 * time.Millisecond
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		replaced := c.Authority.Replaced()
		if err := c.Reconcile(ctx); err != nil {
			c.Errors.Add(1)
			c.Log.Error("reconcile", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			continue
		case <-replaced:
			// Every leaf was dropped. Reconcile mints them again, then the
			// streams are told to push.
			if err := c.Reconcile(ctx); err != nil {
				c.Errors.Add(1)
				c.Log.Error("reconcile", "error", err)
			}
			if c.KickSecrets != nil {
				c.KickSecrets()
			}
			continue
		case <-c.View.Changed():
		case <-c.kickChan():
		}
		// Changes come in bursts (a rollout, a policy and its pods). Let the
		// burst land before building.
		select {
		case <-ctx.Done():
			return
		case <-time.After(settle):
		}
		select {
		case <-c.View.Changed():
		default:
		}
		select {
		case <-c.kickChan():
		default:
		}
	}
}

// Reconcile builds the listener for the node as it is now and hands it to
// Listeners. Before the view has synced it does nothing: a listener built
// from half a view would drop chains that are in use.
func (c *Controller) Reconcile(ctx context.Context) error {
	if !c.View.Synced() {
		return nil
	}
	if err := c.Activity.Refresh(ctx); err != nil {
		// Not fatal: with no reading every name is busy and nothing is removed.
		c.Log.Warn("envoy stats unavailable; no chain will be removed", "error", err)
	}
	// Names retired in an earlier run are swept only once Envoy has accepted
	// the listener that stopped mapping pods to them. From then on no new
	// connection can reach their chains, so a count of zero stays zero.
	if current, acked, _, _ := c.Listeners.Version(); current != "" && acked == current {
		c.Set.Sweep()
	}
	snap := c.View.Snapshot()
	c.Set.Apply(snap.Wanted())

	// A chain is served only for a name whose leaf exists, so Envoy never
	// waits on a certificate that cannot be minted.
	var chains []string
	for _, name := range c.Set.Names() {
		if _, err := c.Authority.Leaf(name); err != nil {
			if errors.Is(err, ca.ErrNoIntermediate) {
				break
			}
			c.Log.Error("mint leaf", "name", name, "error", err)
			continue
		}
		chains = append(chains, name)
	}
	for _, held := range c.Authority.Held() {
		if !c.Set.Contains(held) {
			c.Authority.Forget(held)
		}
	}

	in := xds.Input{Names: chains}
	for _, p := range snap.Pods {
		in.Pods = append(in.Pods, xds.PodNames{Addrs: p.Addrs, Names: c.Set.NamesFor(p.Exact, p.Patterns, p.Passthrough)})
	}
	l, err := c.Config.Egress(in)
	if err != nil {
		return err
	}
	changed, err := c.Listeners.Set(l)
	if err != nil {
		return err
	}
	c.Reconciles.Add(1)
	if changed {
		counts := c.Set.Counts()
		c.Log.Info("listener updated", "chains", len(chains), "pods", len(in.Pods),
			"exact", counts.Exact, "learned", counts.Learned, "over_cap", counts.OverCap)
	}
	return nil
}
