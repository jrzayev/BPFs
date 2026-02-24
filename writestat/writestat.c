#include <linux/sched.h>
#include <linux/fs.h>

typedef struct {
    u64 start_ts;
    u64 size;
    u32 is_sync;
} in_flight_val;

typedef struct {
    u32 pid;
    u32 type;
    char comm[TASK_COMM_LEN];
} agg_key;

typedef struct {
  u64 calls;
  u64 bytes;
  u64 total_lat;
  u64 max_lat;
} agg_val;

BPF_HASH(in_flight, u64, in_flight_val, 10240);
BPF_PERCPU_HASH(stats, agg_key, agg_val, 10240);

int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, const char *buf, size_t count) {
  u64 tid = bpf_get_current_pid_tgid();
  in_flight_val val = {};
  val.start_ts = bpf_ktime_get_ns();
  val.size = count;
  val.is_sync = 0;

  if ((file->f_flags & (O_SYNC | O_DSYNC | O_DIRECT)) > 0) {
    val.is_sync = 1;
  }

  in_flight.update(&tid, &val);

  return 0;
}

int kretprobe__vfs_write(struct pt_regs *ctx) {
  u64 tid = bpf_get_current_pid_tgid();

  in_flight_val *tsp_start = in_flight.lookup(&tid);
  if (tsp_start == 0)
    return 0;

  long ret = PT_REGS_RC(ctx);
  if (ret < 0) {
    in_flight.delete(&tid);
    return 0;
  }

  u64 curr_latency = bpf_ktime_get_ns() - tsp_start->start_ts;

  agg_key key = {};
  key.pid = tid >> 32;
  key.type = tsp_start->is_sync;
  bpf_get_current_comm(&key.comm, sizeof(key.comm));

  agg_val val = {};
  agg_val *tsp_dist = stats.lookup_or_try_init(&key, &val);
  if (tsp_dist == 0) {
    in_flight.delete(&tid);
    return 0;
  }

  tsp_dist->calls += 1;
  tsp_dist->bytes += ret;
  tsp_dist->total_lat += curr_latency;
  tsp_dist->max_lat = curr_latency > tsp_dist->max_lat ? curr_latency : tsp_dist->max_lat;

  in_flight.delete(&tid);
  return 0;
}

int trace_fsync_entry(struct pt_regs *ctx) {
  u64 tid = bpf_get_current_pid_tgid();
  in_flight_val val = {};
  val.start_ts = bpf_ktime_get_ns();
  val.size = 0;
  val.is_sync = 1;

  in_flight.update(&tid, &val);
  return 0;
}

int trace_fsync_return(struct pt_regs *ctx) {
  u64 tid = bpf_get_current_pid_tgid();

  in_flight_val *tsp_start = in_flight.lookup(&tid);
  if (tsp_start == 0)
    return 0;

  long ret = PT_REGS_RC(ctx);
  if (ret < 0) {
    in_flight.delete(&tid);
    return 0;
  }

  u64 curr_latency = bpf_ktime_get_ns() - tsp_start->start_ts;

  agg_key key = {};
  key.pid = tid >> 32;
  key.type = tsp_start->is_sync;
  bpf_get_current_comm(&key.comm, sizeof(key.comm));

  agg_val val = {};
  agg_val *tsp_dist = stats.lookup_or_try_init(&key, &val);
  if (tsp_dist == 0) {
    in_flight.delete(&tid);
    return 0;
  }

  tsp_dist->calls += 1;
  tsp_dist->total_lat += curr_latency;
  tsp_dist->max_lat = curr_latency > tsp_dist->max_lat ? curr_latency : tsp_dist->max_lat;

  in_flight.delete(&tid);
  return 0;
}
