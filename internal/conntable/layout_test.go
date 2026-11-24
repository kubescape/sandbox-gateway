package conntable

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestKeyBytes(t *testing.T) {
	k, err := ParseKey("10.0.0.5:4242")
	if err != nil {
		t.Fatal(err)
	}
	b := k.bytes()
	if len(b) != ConnKeySize || ConnKeySize != 18 {
		t.Fatalf("key is %d bytes, want 18", len(b))
	}
	wantAddr := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 5}
	if !bytes.Equal(b[:16], wantAddr) {
		t.Fatalf("address bytes = %v, want the v4-mapped form %v", b[:16], wantAddr)
	}
	if got := binary.NativeEndian.Uint16(b[16:]); got != 4242 {
		t.Fatalf("port = %d, want 4242 in host byte order", got)
	}
}

// Review focus: Envoy can report one pod address in two spellings.
func TestParseKeyMapped(t *testing.T) {
	a, err := ParseKey("10.0.0.5:4242")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseKey("[::ffff:10.0.0.5]:4242")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a.bytes() != b.bytes() {
		t.Fatalf("%v and %v are different keys", a, b)
	}
	v6, err := ParseKey("[2001:db8::1]:443")
	if err != nil || v6.Addr != netip.MustParseAddr("2001:db8::1") || v6.Port != 443 {
		t.Fatalf("%v %v", v6, err)
	}
}

func TestParseKeyRejects(t *testing.T) {
	for _, in := range []string{"", "10.0.0.5", "10.0.0.5:", "host:80", "[fe80::1%eth0]:80", "10.0.0.5:70000", "/run/x.sock"} {
		if k, err := ParseKey(in); err == nil {
			t.Errorf("ParseKey(%q) = %v, want an error", in, k)
		}
	}
}

func TestConnValueRoundTrip(t *testing.T) {
	for _, c := range []Conn{
		{CgroupID: 0x1122334455667788, PID: 4321, BindingID: 7, OrigDst: netip.MustParseAddrPort("160.79.104.10:443")},
		{CgroupID: 1, PID: 2, BindingID: 3, OrigDst: netip.MustParseAddrPort("[2607:6bc0::10]:443")},
	} {
		b := encodeConn(c)
		if len(b) != ConnValueSize || ConnValueSize != 40 {
			t.Fatalf("value is %d bytes, want 40", len(b))
		}
		got, err := decodeConn(b)
		if err != nil || got != c {
			t.Fatalf("round trip: %+v %v, want %+v", got, err, c)
		}
	}
	// Field offsets, as a C struct with natural alignment lays them out.
	b := encodeConn(Conn{CgroupID: 0x0102030405060708, PID: 0x0a0b0c0d, BindingID: 0x11121314, OrigDst: netip.MustParseAddrPort("1.2.3.4:443")})
	if binary.NativeEndian.Uint64(b[0:]) != 0x0102030405060708 || binary.NativeEndian.Uint32(b[8:]) != 0x0a0b0c0d ||
		binary.NativeEndian.Uint32(b[12:]) != 0x11121314 || b[28] != 1 || b[31] != 4 || binary.NativeEndian.Uint16(b[32:]) != 443 {
		t.Fatalf("layout: % x", b)
	}
	if _, err := decodeConn(b[:39]); err == nil {
		t.Fatal("short value decoded")
	}
}

func TestBindingValue(t *testing.T) {
	if BindingValueSize != 8 {
		t.Fatalf("binding value is %d bytes, want 8", BindingValueSize)
	}
	for posture, want := range map[uint8]string{0: PostureAllow, 1: PostureDeny} {
		b := make([]byte, BindingValueSize)
		binary.NativeEndian.PutUint32(b, 9)
		b[4], b[5] = posture, GateFailingOpen
		got, err := decodeBinding(b)
		if err != nil || got != (Binding{BindingID: 9, Posture: want, Gate: GateFailingOpen}) {
			t.Fatalf("posture %d: %+v %v", posture, got, err)
		}
	}
	bad := make([]byte, BindingValueSize)
	bad[4] = 2
	if _, err := decodeBinding(bad); err == nil {
		t.Fatal("unknown posture byte decoded")
	}
	bad[4], bad[5] = 0, 3
	if _, err := decodeBinding(bad); err == nil {
		t.Fatal("unknown gate byte decoded")
	}
}
