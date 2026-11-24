package conntable

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Wire layout of the pinned maps. Integers are in host byte order; addresses
// are 16 bytes in network order, IPv4 in its IPv6-mapped form. The structs
// have natural C alignment:
//
//	conns key      addr[16] port:u16                                  18 bytes
//	conns value    cgroup:u64 pid:u32 binding:u32 addr[16] port:u16   34 bytes, padded to 40
//	bindings key   cgroup:u64                                          8 bytes
//	bindings value binding:u32 posture:u8 gate:u8                      6 bytes, padded to 8
//
// Open refuses maps whose key or value size differs from these.
const (
	ConnKeySize      = 18
	ConnValueSize    = 40
	BindingKeySize   = 8
	BindingValueSize = 8
)

func (k Key) bytes() [ConnKeySize]byte {
	var b [ConnKeySize]byte
	a := k.Addr.As16()
	copy(b[:16], a[:])
	binary.NativeEndian.PutUint16(b[16:], k.Port)
	return b
}

func decodeConn(b []byte) (Conn, error) {
	if len(b) != ConnValueSize {
		return Conn{}, fmt.Errorf("conntable: conns value is %d bytes, want %d", len(b), ConnValueSize)
	}
	return Conn{
		CgroupID:  binary.NativeEndian.Uint64(b[0:]),
		PID:       binary.NativeEndian.Uint32(b[8:]),
		BindingID: binary.NativeEndian.Uint32(b[12:]),
		OrigDst:   netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[16:32])).Unmap(), binary.NativeEndian.Uint16(b[32:])),
	}, nil
}

func encodeConn(c Conn) []byte {
	b := make([]byte, ConnValueSize)
	binary.NativeEndian.PutUint64(b[0:], c.CgroupID)
	binary.NativeEndian.PutUint32(b[8:], c.PID)
	binary.NativeEndian.PutUint32(b[12:], c.BindingID)
	a := c.OrigDst.Addr().As16()
	copy(b[16:32], a[:])
	binary.NativeEndian.PutUint16(b[32:], c.OrigDst.Port())
	return b
}

func decodeBinding(b []byte) (Binding, error) {
	if len(b) != BindingValueSize {
		return Binding{}, fmt.Errorf("conntable: bindings value is %d bytes, want %d", len(b), BindingValueSize)
	}
	out := Binding{BindingID: binary.NativeEndian.Uint32(b[0:]), Gate: b[5]}
	switch b[4] {
	case 0:
		out.Posture = PostureAllow
	case 1:
		out.Posture = PostureDeny
	default:
		return Binding{}, fmt.Errorf("conntable: unknown posture %d in bindings", b[4])
	}
	if out.Gate > GateRecovering {
		return Binding{}, fmt.Errorf("conntable: unknown gate state %d in bindings", out.Gate)
	}
	return out, nil
}

func encodeBinding(b Binding) []byte {
	out := make([]byte, BindingValueSize)
	binary.NativeEndian.PutUint32(out[0:], b.BindingID)
	if b.Posture == PostureDeny {
		out[4] = 1
	}
	out[5] = b.Gate
	return out
}
