// Command pinmaps creates and pins empty conns and bindings maps of the sizes
// the processor expects, the way node-agent will, so the smoke test can run
// the shipped processor image against real pinned maps. It runs as root.
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kubescape/sandbox-gateway/internal/conntable"
)

func main() {
	dir := flag.String("dir", conntable.DefaultDir, "where to pin the maps")
	uid := flag.Int("uid", 65532, "owner of the pinned maps: the processor's user")
	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("remove the memlock limit: %v", err)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}
	for _, m := range []struct {
		name       string
		key, value uint32
	}{
		{"conns", conntable.ConnKeySize, conntable.ConnValueSize},
		{"bindings", conntable.BindingKeySize, conntable.BindingValueSize},
	} {
		path := filepath.Join(*dir, m.name)
		_ = os.Remove(path)
		bm, err := ebpf.NewMap(&ebpf.MapSpec{Name: m.name, Type: ebpf.Hash, KeySize: m.key, ValueSize: m.value, MaxEntries: 1024})
		if err != nil {
			log.Fatalf("create %s: %v", m.name, err)
		}
		if err := bm.Pin(path); err != nil {
			log.Fatalf("pin %s: %v", path, err)
		}
		// Readable by the processor's user, as node-agent will leave them.
		if err := os.Chown(path, *uid, *uid); err != nil {
			log.Fatalf("chown %s: %v", path, err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			log.Fatalf("chmod %s: %v", path, err)
		}
		_ = bm.Close()
		log.Printf("pinned %s (key %d, value %d bytes), owner %d", path, m.key, m.value, *uid)
	}
}
