//go:build linux

package conntable

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

type pinned struct{ conns, bindings *ebpf.Map }

// Open opens the conns and bindings maps pinned under dir, read-only. It
// fails if either is missing or does not have this package's layout, so a
// processor never runs against tables it would misread.
func Open(dir string) (Table, error) {
	conns, err := openMap(filepath.Join(dir, "conns"), ConnKeySize, ConnValueSize)
	if err != nil {
		return nil, err
	}
	bindings, err := openMap(filepath.Join(dir, "bindings"), BindingKeySize, BindingValueSize)
	if err != nil {
		_ = conns.Close()
		return nil, err
	}
	return &pinned{conns: conns, bindings: bindings}, nil
}

func openMap(path string, keySize, valueSize uint32) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("conntable: open %s: %w", path, err)
	}
	if m.KeySize() != keySize || m.ValueSize() != valueSize {
		_ = m.Close()
		return nil, fmt.Errorf("conntable: %s has key %d and value %d bytes, want %d and %d",
			path, m.KeySize(), m.ValueSize(), keySize, valueSize)
	}
	return m, nil
}

func (p *pinned) Conn(k Key) (Conn, bool, error) {
	key := k.bytes()
	val := make([]byte, ConnValueSize)
	if err := p.conns.Lookup(key[:], &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Conn{}, false, nil
		}
		return Conn{}, false, fmt.Errorf("conntable: conns lookup: %w", err)
	}
	c, err := decodeConn(val)
	return c, err == nil, err
}

func (p *pinned) Binding(cgroupID uint64) (Binding, bool, error) {
	val := make([]byte, BindingValueSize)
	if err := p.bindings.Lookup(cgroupID, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Binding{}, false, nil
		}
		return Binding{}, false, fmt.Errorf("conntable: bindings lookup: %w", err)
	}
	b, err := decodeBinding(val)
	return b, err == nil, err
}
