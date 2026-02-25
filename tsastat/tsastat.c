typedef struct {
    u64 ts;
    u64 state;
} pid_s;

typedef struct {
    u64 run_time;
    u64 sleep_time;
    u64 disk_time;
} stats_t;

BPF_HASH(start, u32, pid_s, 10240);
BPF_PERCPU_HASH(dist, u32, stats_t, 10240);

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    pid_s prev_info = {.ts = ts, .state = args->prev_state};
    start.update(&prev_pid, &prev_info);

    pid_s *tsp_start = start.lookup(&next_pid);
    if (tsp_start == 0)
      return 0;

    u64 delta = ts - tsp_start->ts;

    stats_t zero = {};
    stats_t *tsp_dist = dist.lookup_or_try_init(&next_pid, &zero);
    if (tsp_dist == 0)
      return 0;

    if (tsp_start->state == 0)
      tsp_dist->run_time += delta;
    else if (tsp_start->state & 2)
      tsp_dist->disk_time += delta;
    else
      tsp_dist->sleep_time += delta;

    return 0;
}
