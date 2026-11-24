package extproc

import (
	"strings"
	"sync"
	"time"
)

// positions counts requests per downstream connection, for the record's
// request_position on HTTP/1.x (see docs/features/processor.md, "Request
// position"). Envoy cannot give the processor the HTTP/2 stream id, and the
// order HTTP/2 streams reach the processor is not the order the client opened
// them, so HTTP/2 requests get no position.
//
// A connection is keyed on Envoy's connection.id and the downstream address
// together: connection ids start again when Envoy restarts, the address keeps
// a new connection from continuing an old one's count.
type positions struct {
	mu    sync.Mutex
	now   func() time.Time
	conns map[connKey]*connCount
	// droppedUpTo is the highest connection id the full map turned away.
	// Envoy hands out connection ids in increasing order, so a connection
	// first seen with an id at or below it may be one whose first requests
	// were not counted: it gets no position rather than a wrong one.
	droppedUpTo uint64
	dropped     bool
}

type connKey struct {
	id   uint64
	addr string
}

type connCount struct {
	n    int
	seen time.Time
}

const (
	// positionIdle drops a connection's count once it has been quiet this
	// long: Envoy closes a downstream connection idle for an hour by default.
	positionIdle = time.Hour
	// maxPositions bounds the map; past it, idle connections are pruned.
	maxPositions = 1 << 16
)

func newPositions(now func() time.Time) *positions {
	return &positions{now: now, conns: map[connKey]*connCount{}}
}

// next returns the request's ordinal on its connection, from 1, or 0 when it
// has none: HTTP/2 and later, or no connection id.
func (p *positions) next(connID uint64, hasID bool, addr, protocol string) int {
	if !hasID || !strings.HasPrefix(protocol, "HTTP/1") {
		return 0
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	k := connKey{connID, addr}
	c, ok := p.conns[k]
	if !ok {
		if p.dropped && connID <= p.droppedUpTo {
			return 0
		}
		if len(p.conns) >= maxPositions {
			p.prune(now)
		}
		if len(p.conns) >= maxPositions {
			p.dropped = true
			p.droppedUpTo = max(p.droppedUpTo, connID)
			return 0
		}
		c = &connCount{}
		p.conns[k] = c
	}
	c.n++
	c.seen = now
	return c.n
}

// prune drops connections quiet for positionIdle. Called with mu held.
func (p *positions) prune(now time.Time) {
	for k, c := range p.conns {
		if now.Sub(c.seen) >= positionIdle {
			delete(p.conns, k)
		}
	}
}
