//go:build linux

// Package attrmap reads the stage 1 `conns` map pinned by the redirector:
// downstream ip:port -> original destination, host tgid, namespace pid, cgroup.
package attrmap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/ebpf"
)

type key struct {
	IP   uint32
	Port uint32
}

type value struct {
	DstIP     uint32
	DstPort   uint16
	_         uint16
	TGID      uint32
	NSPID     uint32
	CgroupID  uint64
	ConnectNS uint64
}

// Map is an open pinned conns map.
type Map struct{ m *ebpf.Map }

// Open opens the pinned map at path.
func Open(path string) (*Map, error) {
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	return &Map{m}, nil
}

// Lookup returns the attribution for a downstream "ip:port", or nil.
func (a *Map) Lookup(addr string) (map[string]string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("not ipv4: %s", host)
	}
	p, _ := strconv.Atoi(port)
	var v value
	if err := a.m.Lookup(key{IP: binary.NativeEndian.Uint32(ip), Port: uint32(p)}, &v); err != nil {
		return nil, err
	}
	dst := make(net.IP, 4)
	binary.NativeEndian.PutUint32(dst, v.DstIP)
	dport := v.DstPort>>8 | v.DstPort<<8
	return map[string]string{
		"orig_dst":  fmt.Sprintf("%s:%d", dst, dport),
		"host_pid":  strconv.FormatUint(uint64(v.TGID), 10),
		"ns_pid":    strconv.FormatUint(uint64(v.NSPID), 10),
		"cgroup_id": strconv.FormatUint(v.CgroupID, 10),
		"source":    "5tuple",
	}, nil
}
