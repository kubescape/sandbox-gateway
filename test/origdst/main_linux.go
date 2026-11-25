//go:build linux

// Command origdst is the integration test's stand-in for the part of the redirect that
// lets Envoy learn a connection's original destination. It loads bpf/origdst.bpf.c,
// attaches it to a cgroup, and fills the conns map for whole client addresses, since no
// redirect runs in the test and the clients dial Envoy directly.
//
// It needs root, the host cgroup namespace and a bpffs mount.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
)

func main() {
	obj := flag.String("obj", "/bpf/origdst.bpf.o", "compiled program")
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 directory to attach to; Envoy must run below it")
	pin := flag.String("pin", "/sys/fs/bpf/sandbox-gateway-it", "bpffs directory to pin conns in; removed on exit")
	port := flag.Uint("listener-port", 18443, "the gateway listener's port")
	fill := flag.String("fill", "", "comma-separated client=destination pairs, e.g. 172.30.0.21=172.30.0.30:443: every source port of the client address gets an entry with that original destination")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("remove the memlock limit: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		log.Fatalf("load %s: %v", *obj, err)
	}
	if m := spec.Maps["conns"]; m.KeySize != conntable.ConnKeySize || m.ValueSize != conntable.ConnValueSize {
		log.Fatalf("conns is %d/%d bytes in the program, the processor reads %d/%d", m.KeySize, m.ValueSize, conntable.ConnKeySize, conntable.ConnValueSize)
	}
	if err := spec.Variables["listen_port"].Set(uint16(*port)); err != nil {
		log.Fatalf("set the listener port: %v", err)
	}
	_ = os.RemoveAll(*pin)
	if err := os.MkdirAll(*pin, 0o755); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(*pin) }()
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: *pin}})
	if err != nil {
		log.Fatalf("load the program: %v", err)
	}
	defer coll.Close()

	for _, pair := range strings.Split(*fill, ",") {
		client, dst, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		src, err := netip.ParseAddr(client)
		if err != nil {
			log.Fatalf("-fill: %v", err)
		}
		to, err := netip.ParseAddrPort(dst)
		if err != nil {
			log.Fatalf("-fill: %v", err)
		}
		value := make([]byte, conntable.ConnValueSize)
		d := to.Addr().As16()
		copy(value[16:32], d[:])
		binary.NativeEndian.PutUint16(value[32:], to.Port())
		s := src.As16()
		for p := 1; p < 65536; p++ {
			key := make([]byte, conntable.ConnKeySize)
			copy(key, s[:])
			binary.NativeEndian.PutUint16(key[16:], uint16(p))
			if err := coll.Maps["conns"].Put(key, value); err != nil {
				log.Fatalf("fill conns: %v", err)
			}
		}
		log.Printf("conns: every port of %s -> %s", src, to)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{Path: *cgroup, Attach: ebpf.AttachCGroupGetsockopt, Program: coll.Programs["origdst"]})
	if err != nil {
		log.Fatalf("attach to %s: %v", *cgroup, err)
	}
	defer func() { _ = l.Close() }()
	log.Printf("attached: SO_ORIGINAL_DST on port %d is answered from conns", *port)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
}
