//
// Created by jr-free on 9/30/26.
//

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)


func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memory lock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF failed: %v", err)
	}
	defer objs.Close()

	fmt.Println("eBPF objects loaded")

	prm := bpfParm{
		Enabled: 1,
		TargetUid: 1000,
		MatchAllUsers: 0,
	}
	key := uint32(0)
	if err := objs.ParmMap.Update(&key, &prm, ebpf.UpdateAny); err != nil {
		log.Fatalf("writing config: %v", err)
	}

	fn, err := link.AttachTracing(link.TracingOptions{
		Program: objs.DoUnlinkatAudit,
	})

	if err != nil {
		log.Fatalf("failed to attach fentry: %v", err)
	}
	defer fn.Close()
	fmt.Println("Fentry attached to do_unlinkat")
	
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	for {
		select {
			case<-stop:
			log.Println("\n")
			log.Println("Shutting down...")
			return
		default:
			var seenVal uint64 = 0
			var seenKey uint32 = 0
			objs.CounterMap.Lookup(&seenKey, &seenVal)
	
			var matchVal uint64 = 0
			var matchKey uint32 = 1
			objs.CounterMap.Lookup(&matchKey, &matchVal)

			var skippedVal uint64 = 0
			var skippedKey uint32 = 2
			objs.CounterMap.Lookup(&skippedKey, &skippedVal)

			log.Printf("seen=%d  matched=%d  skipped=%d", 
			seenVal, matchVal, skippedVal)

			time.Sleep(2 * time.Second)
		}
	}
}
