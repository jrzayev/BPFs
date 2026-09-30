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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing Memlock: ", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}

	defer objs.Close()
	fmt.Println("eBPF objects loaded")

	kp, err := link.Kprobe("kernel_clone", objs.TraceKernelClone, nil)
	if err != nil {
		log.Fatal("Attach failed: ", err)
	}
	defer kp.Close()
	fmt.Println("Attached to process creation")


	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	var lostKey uint32 = 0
	var lostValue uint64 = 0

	for {
		select {
		case <-stopper:
			log.Println("\n")
			log.Println("Shutting down...")
			log.Printf("Done. Total lost observed: %d", lostValue)
			return
		default:
			objs.LostCount.Lookup(&lostKey, &lostValue)
			iter := objs.ChildCount.Iterate()
			var key uint32
			var value uint64
			for iter.Next(&key, &value) {
				log.Printf(" PID %d: created %d childrens", key, value)
			}

			if err := iter.Err(); err != nil {
				log.Printf("iterator error: %v", err)
			}

			time.Sleep(1 * time.Second)
		}
	}
	
}
