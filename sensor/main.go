//
// Crated by Javid Rzayev 10/1/2026
//

package main

import (
  "bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
  "sort"
  "strconv"
  "strings"
  "time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
  "github.com/cilium/ebpf/rlimit"
  "github.com/cilium/ebpf"
  "golang.org/x/sys/unix"
)

type pidStat struct {
  pid uint32
  info bpfInfo
}

func readDropped(objs *bpfObjects) uint64 {
  var total uint64
  for key := uint32(0); key < 6; key++ {
    var v uint64
    if err := objs.Losts.Lookup(&key, &v); err == nil {
      total += v
    }
  }
  return total
}

func printStats(objs *bpfObjects) {
  var stats []pidStat
  var pid uint32
  var info bpfInfo

  iter := objs.Infos.Iterate()
  for iter.Next(&pid, &info) {
    stats = append(stats, pidStat{pid: pid, info: info})
  }

  if err := iter.Err(); err != nil {
    log.Printf("Iterating infos: %v", err)
    return
  }

  sort.Slice(stats, func(i, j int) bool {
    a := stats[i].info.ExecCount + stats[i].info.DeleteCount + stats[i].info.SpawnCount
    b := stats[j].info.ExecCount + stats[j].info.DeleteCount + stats[j].info.SpawnCount
    return a > b
  })

  fmt.Printf("-- stats --  tracked=%d dropped=%d\n", len(stats), readDropped(objs))
  for i := 0; i < len(stats) && i < 5; i++ {
    comm := "unknown"
    if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", stats[i].pid)); err == nil {
      comm = strings.TrimSpace(string(b))
    }
    fmt.Printf("   PID %d %s: exec=%d del=%d spawn=%d\n",
      stats[i].pid, comm, stats[i].info.ExecCount, stats[i].info.DeleteCount,
      stats[i].info.SpawnCount)
  }
}

func main() {
  if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memory lock: %v", err)
	}

  var objs bpfObjects
  if err := loadBpfObjects(&objs, nil); err != nil {
    log.Fatal("Loading eBPF objects: ", err)
  }
  defer objs.Close()
  fmt.Println("eBPF objects loaded")

  prm := bpfParm{
    Root: 1,
    Status: 1,
    DeleteLimit: 30,
    SpawnLimit: 30,
    ExecLimit: 30,
	}
	key := uint32(0)
  if err := objs.Parms.Update(&key, &prm, ebpf.UpdateAny); err != nil {
		log.Fatalf("writing config: %v", err)
	}

  kp, err := link.Kprobe("kernel_clone", objs.SensorKpKernelClone, nil)
  if err != nil {
    log.Fatalf("SensorKpKernelClone attach failed: %v", err)
  }
  defer kp.Close()
  fmt.Println("Kprobe attached to kernel_clone")

  fn, err := link.AttachTracing(link.TracingOptions{
    Program: objs.SensorFnDoUnlinkat,
  })
  if err != nil {
    log.Fatalf("SensorFnDoUnlinkat attach failed: %v", err)
  }
  defer fn.Close()
  fmt.Println("Fentry attached to do_unlinkat")

  tp, err := link.Tracepoint("sched", "sched_process_exec",
    objs.SensorTpSchedProcessExec, nil)
  if err != nil {
    log.Fatalf("SensorTpSchedProcessExec attach failed: %v", err)
  }
  defer tp.Close()
  fmt.Println("Tracepoint attached to sched/sched_process_exec")

  fmt.Println("All 3 programs attached")
  fmt.Println("Config: root=on resume=on delete-limit=30 spawn-limit=30 exec-limit=30")

  fmt.Println("Commands: root on|off, delete-limit <n>, spawn-limit <n>, pause, resume")
  rd, err := ringbuf.NewReader(objs.Events)
  if err != nil {
    log.Fatalf("Failed to open ringbuf reader: %v", err)
  }
  defer rd.Close()

  stop := make(chan os.Signal, 1)
  signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

  go func() {
    <-stop
    rd.Close()
  }()

  go func() {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
      args := strings.Fields(scanner.Text())
      if len(args) == 0 {
        continue
      }
      ok := true
      switch args[0] {
      case "root":
        if len(args) == 2 && args[1] == "on" {
          prm.Root = 1
        } else if len(args) == 2 && args[1] == "off" {
          prm.Root = 0
        } else {
          ok = false
        }
      case "delete-limit":
        if len(args) != 2 {
          ok = false
          break
        }
        n, err := strconv.ParseUint(args[1], 10, 32)
        if err != nil {
          ok = false
          break
        }
        prm.DeleteLimit = uint32(n)
      case "spawn-limit":
        if len(args) != 2 {
          ok = false
          break
        }
        n, err := strconv.ParseUint(args[1], 10, 32)
        if err != nil {
          ok = false
          break
        }
        prm.SpawnLimit = uint32(n)
      case "exec-limit":
        if len(args) != 2 {
          ok = false
          break
        }
        n, err := strconv.ParseUint(args[1], 10, 32)
        if err != nil {
          ok = false
          break
        }
        prm.ExecLimit = uint32(n)
      case "pause":
        prm.Status = 0
      case "resume":
        prm.Status = 1
      default:
        ok = false
      }

      if !ok {
        fmt.Println("unknown command. ")
        fmt.Println("use: root on|off, delete-limit <n>, spawn-limit <n>, pause, resume")
        continue
      }
      if err := objs.Parms.Update(&key, &prm, ebpf.UpdateAny); err != nil {
        log.Printf("writing config: %v", err)
        continue
      }
      fmt.Printf("Config updated: root=%d status=%d delete-limit=%d spawn-limit=%d exec-limit=%d\n",
        prm.Root, prm.Status, prm.DeleteLimit, prm.SpawnLimit, prm.ExecLimit)
    }
  }()

  ticker := time.NewTicker(10 * time.Second)
  go func() {
    for range ticker.C {
      printStats(&objs)
    }
  }()

  var tsFirst uint64
  var alarmCount uint64
  alarmTypes := []string{"ROOT_EXEC", "ROOT_DELETE", "ROOT_SPAWN",
    "DELETE_LIMIT", "SPAWN_LIMIT", "EXEC_LIMIT"}

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
    if err := binary.Read(bytes.NewReader(record.RawSample),
      binary.LittleEndian, &event); err != nil {
        log.Printf("parsing event: %v", err)
  			continue
  	}

    if event.AlertType > 5 || event.AlertType < 0 {
      continue
    }
    
    if tsFirst == 0 {
      tsFirst = event.Ts
    }
    alarmCount++
		comm := unix.ByteSliceToString(event.Comm[:])
    fmt.Printf("+%.3fs %s pid=%d uid=%d comm=%s\n",
      float64(event.Ts-tsFirst)/1e9, alarmTypes[event.AlertType], event.Pid, event.Uid, comm)
	}

  ticker.Stop()
  fmt.Println()
  fmt.Printf("-- total --  alarms=%d dropped=%d\n", alarmCount, readDropped(&objs))
}
