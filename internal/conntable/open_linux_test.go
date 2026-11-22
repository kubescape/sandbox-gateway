//go:build linux

package conntable

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// pinDir returns a fresh directory on bpffs, or skips: creating and pinning
// maps needs root and a mounted bpffs.
func pinDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create BPF maps")
	}
	_ = rlimit.RemoveMemlock()
	dir, err := os.MkdirTemp("/sys/fs/bpf", "conntable-test-")
	if err != nil {
		t.Skipf("no writable bpffs at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func pinMap(t *testing.T, dir, name string, keySize, valueSize uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: name, Type: ebpf.Hash, KeySize: keySize, ValueSize: valueSize, MaxEntries: 16})
	if err != nil {
		t.Skipf("cannot create a BPF map here: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.Pin(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestOpenReadsPinnedMaps(t *testing.T) {
	dir := pinDir(t)
	conns := pinMap(t, dir, "conns", ConnKeySize, ConnValueSize)
	bindings := pinMap(t, dir, "bindings", BindingKeySize, BindingValueSize)

	key, _ := ParseKey("10.0.0.5:4242")
	want := Conn{CgroupID: 77, PID: 1234, BindingID: 3, OrigDst: netip.MustParseAddrPort("160.79.104.10:443")}
	kb := key.bytes()
	if err := conns.Put(kb[:], encodeConn(want)); err != nil {
		t.Fatal(err)
	}
	wantB := Binding{BindingID: 3, Posture: PostureDeny, Gate: GateRecovering}
	if err := bindings.Put(uint64(77), encodeBinding(wantB)); err != nil {
		t.Fatal(err)
	}

	tbl, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := tbl.Conn(key); err != nil || !ok || got != want {
		t.Fatalf("Conn = %+v %v %v, want %+v", got, ok, err, want)
	}
	// The mapped spelling of the same address finds the same entry.
	mapped, _ := ParseKey("[::ffff:10.0.0.5]:4242")
	if _, ok, err := tbl.Conn(mapped); err != nil || !ok {
		t.Fatalf("mapped address missed: %v %v", ok, err)
	}
	other, _ := ParseKey("10.0.0.5:4243")
	if _, ok, err := tbl.Conn(other); err != nil || ok {
		t.Fatalf("another port matched: %v %v", ok, err)
	}
	if got, ok, err := tbl.Binding(77); err != nil || !ok || got != wantB {
		t.Fatalf("Binding = %+v %v %v, want %+v", got, ok, err, wantB)
	}
	if _, ok, err := tbl.Binding(78); err != nil || ok {
		t.Fatalf("unbound cgroup matched: %v %v", ok, err)
	}
}

func TestOpenRejectsWrongSizes(t *testing.T) {
	dir := pinDir(t)
	pinMap(t, dir, "conns", 8, 24) // the layout the proof of concept used
	pinMap(t, dir, "bindings", BindingKeySize, BindingValueSize)
	if _, err := Open(dir); err == nil {
		t.Fatal("Open accepted a conns map with another layout")
	}
}

func TestOpenMissing(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nothing-here")); err == nil {
		t.Fatal("Open succeeded with no maps")
	}
}
