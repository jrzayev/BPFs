//
// Created by jr-free on 9/30/26.
//

package main

import (
	"fmt"
	"log"
	"time"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}

	defer objs.Close()
	fmt.Println("eBPF objects loaded")

	kp, err := link.Kprobe("__x64_sys_kill", objs.SysKillCount, nil)

	if err != nil {
		log.Fatalf("attach failed: %v", err)
	}
	defer kp.Close()

	fmt.Println("kprobe attached to kill syscall")
	fmt.Println("Watching kill() calls. Press Ctrl+C to stop.")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	var key uint32 = 0

	for {
		select {
		case <-stopper:
			log.Println("Shutting down...")
			return
		default:
			var value uint64
			err = objs.KillCount.Lookup(&key, &value)
			if err == nil {
				log.Printf("kill() calls since start: %d", value)
			}
			time.Sleep(1 * time.Second)
		}
	}
}
