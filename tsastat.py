import time
from bcc import BPF
from bcc.utils import printb

"""
tsastat - Thread State Analysis Tool using eBPF

Description:
    This tool traces kernel scheduler switches (`sched:sched_switch`) to measure
    time spent by threads in different states.

     - RUN (Runnable)
     - DISK (Uninterruptible)
     - SLEEP (Interruptible)

Output:
    Updates every second, showing cumulative time (in ms) for each active PID.
"""


b = BPF(text="""
typedef struct {
    u64 ts;
    u64 state;
} pid_s;

typedef struct {
    u64 run_time;
    u64 sleep_time;
    u64 disk_time;
} stats_t;

BPF_HASH(start, u32, pid_s);
BPF_HASH(dist, u32, stats_t);

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 ts = bpf_ktime_get_ns();

    u32 prev_pid = args->prev_pid;
    pid_s prev_info = {};
    prev_info.ts = ts;
    prev_info.state = args->prev_state;
    start.update(&prev_pid, &prev_info);

    u32 next_pid = args->next_pid;
    pid_s *tsp_start = start.lookup(&next_pid);

    if (tsp_start != 0) {
        u64 delta = ts - tsp_start->ts;
        stats_t *tsp_dist = dist.lookup(&next_pid);

        if (tsp_dist == 0) {
            stats_t zero = {};
            dist.update(&next_pid, &zero);
            tsp_dist = dist.lookup(&next_pid);
        }

        if (tsp_dist != 0) {
            if (tsp_start->state == 0)
                tsp_dist->run_time += delta;
            else if (tsp_start->state == 2)
                tsp_dist->disk_time += delta;
            else
                tsp_dist->sleep_time += delta;
        }
    }


	return 0;
}
"""
)

print("%-10s %-10s %-10s %-10s" % ("PID", "RUN(ms)", "SLEEP(ms)", "DISK(ms)"))

while True:
    try:
        time.sleep(1)
        for k, v in b["dist"].items():
            print("%-10d %-10d %-10d %-10d" % (
                k.value,
                v.run_time / 1000000,
                v.sleep_time / 1000000,
                v.disk_time / 1000000
            ))
        b["dist"].clear()
        print("-" * 40)

    except KeyboardInterrupt:
        print("\nTschüss!")
        exit()
