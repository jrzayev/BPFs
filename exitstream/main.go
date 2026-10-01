//
// Created by Javid Rzayev 01/10/2026
//

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
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

	tp, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceSysExit, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		rd.Close()
	}()

	var first uint64
	var count uint64

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		var event bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		if first == 0 {
			first = event.Ts
		}
		count++

		thread := ""
		if event.Tid != event.Pid {
			thread = " (thread)"
		}

		comm := unix.ByteSliceToString(event.Comm[:])
		fmt.Printf("+%.3fs pid=%d tid=%d uid=%d comm=%s%s\n",
			float64(event.Ts-first)/1e9, event.Pid, event.Tid, event.Uid, comm, thread)
	}

	var key uint32
	var dropped uint64
	if err := objs.Drops.Lookup(&key, &dropped); err != nil {
		log.Printf("reading drops: %v", err)
	}

	fmt.Printf("\nevents=%d dropped=%d\n", count, dropped)
}
