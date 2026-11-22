// Package conntable reads the two kernel tables node-agent pins for the
// gateway: conns, which says which pod socket a connection came from, and
// bindings, which holds each bound pod's fail posture and health-gate state.
//
// These tables are the only identity source the processor has. Nothing a
// client sends is used to decide who it is.
package conntable

import (
	"fmt"
	"net/netip"
)

// DefaultDir is where node-agent pins the maps.
const DefaultDir = "/sys/fs/bpf/kubescape-sandbox/http"

// Fail postures, as the plugin interface spells them.
const (
	PostureAllow = "allow"
	PostureDeny  = "deny"
)

// Health-gate states of a binding.
const (
	GateRedirecting uint8 = 0
	GateFailingOpen uint8 = 1
	GateRecovering  uint8 = 2
)

// Key identifies a connection by the pod socket's own address and port. Seen
// from Envoy that is the downstream remote address (source.address). Envoy's
// downstream local address is the listener, the same for every connection,
// and is never the key.
type Key struct {
	Addr netip.Addr
	Port uint16
}

// ParseKey reads Envoy's source.address ("ip:port" or "[ip]:port"). An IPv4
// address written in its IPv6-mapped form gives the same key as the plain one.
func ParseKey(sourceAddress string) (Key, error) {
	ap, err := netip.ParseAddrPort(sourceAddress)
	if err != nil {
		return Key{}, fmt.Errorf("conntable: source address %q: %w", sourceAddress, err)
	}
	if ap.Addr().Zone() != "" {
		return Key{}, fmt.Errorf("conntable: source address %q has a zone", sourceAddress)
	}
	return Key{Addr: ap.Addr().Unmap(), Port: ap.Port()}, nil
}

func (k Key) String() string { return netip.AddrPortFrom(k.Addr, k.Port).String() }

// Conn is what the kernel recorded for one redirected connection.
type Conn struct {
	CgroupID  uint64
	PID       uint32
	BindingID uint32
	OrigDst   netip.AddrPort // where the pod was connecting to
}

// Binding is a bound pod's entry.
type Binding struct {
	BindingID uint32
	Posture   string // PostureAllow or PostureDeny
	Gate      uint8  // GateRedirecting, GateFailingOpen or GateRecovering
}

// Table reads the two maps. Implementations are safe for concurrent use.
type Table interface {
	// Conn returns the entry for a connection. ok is false when there is none.
	Conn(Key) (c Conn, ok bool, err error)
	// Binding returns the entry for a pod's cgroup. ok is false when the pod
	// is not bound.
	Binding(cgroupID uint64) (b Binding, ok bool, err error)
}
