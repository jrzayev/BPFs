//
// Crated by Javid Rzayev 10/5/2026
//

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"
	"sync/atomic"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type info struct {
	tid     uint32
	on      uint64
	off     uint64
	goid    uint64
	hasGoid bool
}

type goRow struct {
	goid     uint64
	state    string
	on       uint64
	runnable uint64
	waiting  uint64
	koff     uint64
}

func getState(val uint32) string {
	switch val {
	case 0:
		return "IDLE"
	case 1:
		return "RUNNABLE"
	case 2:
		return "RUNNING"
	case 3:
		return "SYSCALL"
	case 4:
		return "WAITING"
	case 5:
		return "MORIBUND_UNUSED"
	case 6:
		return "DEAD"
	case 7:
		return "ENQUEUE_UNUSED"
	case 8:
		return "COPYSTACK"
	case 9:
		return "PREEMPTED"
	default:
		return "UNKNOWN"
	}
}

func monoNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

func main() {
	var v bool
	flag.BoolVar(&v, "v", false, "print every goroutine state event")
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatalf("usage: %s [-v] <target-pid>", os.Args[0])
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memory lock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF failed: %v", err)
	}
	defer objs.Close()
	fmt.Println("eBPF objects loaded")

	pid, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		log.Fatalf("Invalid pid %q: %v", flag.Arg(0), err)
	}
	err = objs.UserspaceConfig.Put(uint32(0), uint32(pid))
	if err != nil {
		log.Fatalf("Update UserspaceConfig failed: %v", err)
	}

	processPath := fmt.Sprintf("/proc/%d/exe", pid)
	resolvedLink, err := os.Readlink(processPath)
	if err != nil {
		log.Fatalf("Invalid resolve %d proc path: %v", pid, err)
	}
	fmt.Printf("Using binary path %s\n", resolvedLink)
	up, err := link.OpenExecutable(processPath)
	if err != nil {
		log.Fatalf("OpenExecutable go binary: %v", err)
	}

	probe, err := up.Uprobe("runtime.casgstatus",
		objs.UprobeRuntimeCasgstatus, &link.UprobeOptions{
			PID: pid,
		})
	if err != nil {
		log.Fatalf("Uprobe runtime.casgstatus: %v", err)
	}
	defer probe.Close()

	tr, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TpBtfSchedSwitch,
	})
	if err != nil {
		log.Fatalf("Attaching Tracing: %v", err)
	}
	defer tr.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	srd, err := ringbuf.NewReader(objs.Summaries)
	if err != nil {
		log.Fatalf("Failed to open summaries reader: %v", err)
	}
	defer srd.Close()

	var finishedOn atomic.Uint64

	go func() {
		for {
			record, err := srd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Reading summaries: %v", err)
				continue
			}
			var s bpfGoidSummary
			if err := binary.Read(bytes.NewReader(record.RawSample),
				binary.LittleEndian, &s); err != nil {
				log.Printf("Parsing summary: %v", err)
				continue
			}
			finishedOn.Add(s.On)
			fmt.Printf("[done] goid=%d on=%.3fms runnable=%.3fms waiting=%.3fms koff=%.3fms\n",
				s.Goid, float64(s.On)/1e6, float64(s.Runnable)/1e6,
				float64(s.Waiting)/1e6, float64(s.KernelOff)/1e6)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})

	go func() {
		<-stop
		close(done)
		rd.Close()
		srd.Close()
	}()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				var rows []info
				var tid uint32
				var ts uint64
				now := monoNow()

				iter := objs.TidLastSwitch.Iterate()
				for iter.Next(&tid, &ts) {
					row := info{tid: tid}
					_ = objs.OnNs.Lookup(tid, &row.on)
					_ = objs.OffNs.Lookup(tid, &row.off)
					row.hasGoid = objs.TidToGoid.Lookup(tid, &row.goid) == nil
					rows = append(rows, row)
				}
				if err := iter.Err(); err != nil {
					log.Printf("iterator error: %v", err)
				}

				sort.Slice(rows, func(i, j int) bool {
					return rows[i].tid < rows[j].tid
				})

				var sumThreads uint64
				fmt.Println("---------------------------------------------------------")
				fmt.Printf("%-10s %-8s %12s %12s %7s\n",
					"TID", "GOID", "ON(ms)", "OFF(ms)", "ON%")
				for _, r := range rows {
					sumThreads += r.on
					goid := "-"
					if r.hasGoid {
						goid = strconv.FormatUint(r.goid, 10)
					}
					pct := 0.0
					if total := r.on + r.off; total > 0 {
						pct = float64(r.on) * 100 / float64(total)
					}
					fmt.Printf("%-10d %-8s %12.3f %12.3f %6.1f%%\n",
						r.tid, goid, float64(r.on)/1e6, float64(r.off)/1e6, pct)
				}

				var grows []goRow
				var goid uint64
				var cur bpfGoidCur

				giter := objs.GoidState.Iterate()
				for giter.Next(&goid, &cur) {
					g := goRow{goid: goid, state: getState(cur.CurrState)}
					_ = objs.GoidOnNs.Lookup(goid, &g.on)
					var off bpfGoidOffVal
					if objs.GoidOff.Lookup(goid, &off) == nil {
						g.runnable = off.Runnable
						g.waiting = off.Waiting
						g.koff = off.KernelOff
					}
					if now > cur.Ts {
						open := now - cur.Ts
						switch cur.CurrState {
						case 1:
							g.runnable += open
						case 4:
							g.waiting += open
						}
					}
					grows = append(grows, g)
				}
				if err := giter.Err(); err != nil {
					log.Printf("goid iterator error: %v", err)
				}

				var rt uint64
				if objs.GoidOnNs.Lookup(uint64(0), &rt) == nil {
					grows = append(grows, goRow{goid: 0, state: "-", on: rt})
				}

				sort.Slice(grows, func(i, j int) bool {
					return grows[i].on > grows[j].on
				})

				var sumGoroutines uint64
				fmt.Printf("\n%-9s %-9s %12s %12s %12s %12s\n",
					"GOID", "STATE", "ON(ms)", "RUNNABLE", "WAITING", "KERN_OFF")
				for _, g := range grows {
					sumGoroutines += g.on
					name := strconv.FormatUint(g.goid, 10)
					if g.goid == 0 {
						name = "runtime"
					}
					fmt.Printf("%-9s %-9s %12.3f %12.3f %12.3f %12.3f\n",
						name, g.state, float64(g.on)/1e6, float64(g.runnable)/1e6,
						float64(g.waiting)/1e6, float64(g.koff)/1e6)
				}

				fin := finishedOn.Load()
				fmt.Printf("\nsum threads = %.3f ms, sum goroutines = %.3f ms (alive %.3f + finished %.3f)\n",
					float64(sumThreads)/1e6, float64(sumGoroutines+fin)/1e6,
					float64(sumGoroutines)/1e6, float64(fin)/1e6)

			case <-done:
				return
			}
		}
	}()

	var first uint64
	var count uint64

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Reading ringbuf: %v", err)
			continue
		}

		var event bpfEvent
		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian,
			&event)
		if err != nil {
			log.Printf("Parsing event: %v", err)
			continue
		}

		if first == 0 {
			first = event.Ts
		}
		count++

		if v {
			newState := getState(event.NewState)
			oldState := getState(event.OldState)
			fmt.Printf("+%.3fs pid=%d tid=%d goid=%d oldState=%s newState=%s\n",
				float64(event.Ts-first)/1e9, event.Pid, event.Tid, event.Goid,
				oldState, newState)
		}
	}

	fmt.Println("Counts:", count)
}
