#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "openlat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct start_data {
  u64 ts;
  char filename[MAX_FILENAME_LEN];
};


struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u32);
  __type(value, struct start_data);
} start SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} ring_buff SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct hist);
} hists SEC(".maps");


static struct hist zero;
const volatile __u64 min_event_us = 1000;
const volatile bool per_process = false;
const volatile int target_pid = 0;
const volatile char target_comm[TASK_COMM_LEN];
const volatile __u64 target_min_us = 0;
const volatile bool milliseconds = false;


SEC("tp/syscalls/sys_enter_openat")
int file_open(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;
  struct start_data data = {};

  __u32 pid = pid_tgid >> 32;
  if (target_pid && target_pid != pid) {
    return 0;
  }

  char curr_comm[TASK_COMM_LEN];
  bpf_get_current_comm(&curr_comm, sizeof(curr_comm));
  if (target_comm[0] != '\0' &&
    bpf_strcmp(curr_comm, (const char *)target_comm) != 0) {
      return 0;
  }

  data.ts = bpf_ktime_get_ns();
  bpf_probe_read_user_str(data.filename, sizeof(data.filename),
    (const char *)ctx->args[1]);
  bpf_map_update_elem(&start, &tid, &data, BPF_ANY);

  return 0;
}


SEC("tp/syscalls/sys_exit_openat")
int file_close(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;

  struct start_data *start_time = bpf_map_lookup_elem(&start, &tid);
  if (start_time == 0) {
    return 0;
  }

  if (ctx->ret < 0) {
    goto tschuss;
  }

  u64 delta = bpf_ktime_get_ns() - start_time->ts;
  delta /= 1000;
  u64 hist_val = milliseconds ? (delta / 1000) : delta;
  if (target_min_us && delta < target_min_us) {
    goto tschuss;
  }

  u32 pid = pid_tgid >> 32;
  u32 key = per_process ? (pid_tgid >> 32) : 0;
  struct hist *histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
  if (!histp) {
    goto tschuss;
  }

  if (!histp->comm[0]) {
    bpf_get_current_comm(&histp->comm, sizeof(histp->comm));
  }

  u64 slot = log2l(hist_val);
  if (slot >= MAX_SLOTS) {
    slot = MAX_SLOTS - 1;
  }

  __sync_fetch_and_add(&histp->slots[slot], 1);

  if (delta >= min_event_us) {
    struct event *poll_event;
    poll_event = bpf_ringbuf_reserve(&ring_buff, sizeof(*poll_event), 0);
    if (poll_event) {
      poll_event->pid = pid;
      poll_event->delta_us = delta;
      bpf_get_current_comm(&poll_event->comm, sizeof(poll_event->comm));
      __builtin_memcpy(&poll_event->filename, start_time->filename,
        sizeof(poll_event->filename));
      bpf_ringbuf_submit(poll_event, 0);
    }
  }

tschuss:
  bpf_map_delete_elem(&start, &tid);
  return 0;
}
