//
// Created by jr-free on 10/1/26.
//

package main

import (
  "fmt"
  "log"
  "net"
  "os"
  "os/signal"
  "sort"
  "syscall"
  "time"

  "github.com/cilium/ebpf"
  "github.com/cilium/ebpf/rlimit"
  "github.com/cilium/ebpf/link"
)

type remoteStat struct {
  ip string
  bpfInfo
}


func main() {
  if err := rlimit.RemoveMemlock(); err != nil {
    log.Fatalf("Remove memory lock: %v", err)
  }

  var objs bpfObjects
  if err := loadBpfObjects(&objs, nil); err != nil {
    log.Fatalf("Loading eBPF objects: %v", err)
  }
  defer objs.Close()

  iface, err := net.InterfaceByName("lo")
  if err != nil {
    log.Fatalf("Finding lo interface: %v", err)
  }

  ingressTcLink, err := link.AttachTCX(link.TCXOptions{
    Program: objs.TcStatIngress,
    Interface: iface.Index,
    Attach: ebpf.AttachTCXIngress,
  })
  if err != nil {
    log.Fatalf("Attaching Ingress TC: %v", err)
  }
  defer ingressTcLink.Close()

  egressTcLink, err := link.AttachTCX(link.TCXOptions{
    Program: objs.TcStatEgress,
    Interface: iface.Index,
    Attach: ebpf.AttachTCXEgress,
  })
  if err != nil {
    log.Fatalf("Attaching Egress TC: %v", err)
  }
  defer egressTcLink.Close()

  fmt.Println("TCX ingress + egress attached to lo")

  stop := make(chan os.Signal, 1)
  signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

  ticker := time.NewTicker(3 * time.Second)
  defer ticker.Stop()

  for {
    select {
      case <-ticker.C:
        printStats(&objs)
      case <-stop:
        log.Println("\n")
        log.Println("Shutting down...")
      return
    }
  }
}

func printStats(objs *bpfObjects) {
  var stats []remoteStat
  var (
    ip uint32
    info bpfInfo
  )

  iter := objs.RemoteIpsMap.Iterate()
  for iter.Next(&ip, &info) {
    stats = append(stats, remoteStat{
      ip: intToIP(ip),
      bpfInfo: info,
    })
  }
  if err := iter.Err(); err != nil {
    log.Printf("Iterating remote IP map: %v", err)
    return
  }

  sort.Slice(stats, func(i, j int) bool {
    return stats[i].RxBytes+stats[i].TxBytes >
    stats[j].RxBytes+stats[j].TxBytes
  })

  if len(stats) > 10 {
    stats = stats[:10]
  }

  fmt.Printf("[%s]\n", time.Now().Format("15:04:05"))
  fmt.Printf("  %-16s %-8s %-10s %-8s %-10s\n",
    "REMOTE IP", "RX PKTS", "RX BYTES", "TX PKTS", "TX BYTES")

  for _, s := range stats {
    fmt.Printf("  %-16s %-8d %-10d %-8d %-10d\n",
      s.ip, s.RxPackets, s.RxBytes, s.TxPackets, s.TxBytes)
  }

  fmt.Println()
}

func intToIP(v uint32) string {
  return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
}
