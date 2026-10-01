package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	TCP   = 0
	UDP   = 1
	ICMP  = 2
	OTHER = 3
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memory lock: %v", err)
	}

	var objs bpfObjects

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatalf("finding lo: %v", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProtoCount,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attaching XDP: %v", err)
	}
	defer xdpLink.Close()

	fmt.Println("XDP attached to lo (generic mode)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			printStats(objs.ProtoMap)
		case <-sig:
			return
		}
	}
}

func printStats(m *ebpf.Map) {
	var values [4]bpfInfo

	for key := uint32(0); key < 4; key++ {
		var value bpfInfo

		if err := m.Lookup(&key, &value); err != nil {
			log.Printf("map lookup key %d: %v", key, err)
			continue
		}

		values[key] = value
	}

	fmt.Printf("\033[2J\033[H")
	fmt.Println("PROTO   PACKETS   BYTES")
	fmt.Printf("TCP     %-9d %d\n", values[TCP].Packets, values[TCP].Bytes)
	fmt.Printf("UDP     %-9d %d\n", values[UDP].Packets, values[UDP].Bytes)
	fmt.Printf("ICMP    %-9d %d\n", values[ICMP].Packets, values[ICMP].Bytes)
	fmt.Printf("OTHER   %-9d %d\n", values[OTHER].Packets, values[OTHER].Bytes)
}
