#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "openlat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile int pid_target = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} start SEC(".maps");

static struct hist zero;

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");


SEC("tp/syscalls/sys_enter_openat")
int file_open(struct trace_event_raw_sys_enter* ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;

	__u32 pid = pid_tgid >> 32;
  if (pid_target && pid_target != pid) {
      return false;
  }
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
	return 0;
}


SEC("tp/syscalls/sys_exit_openat")
int file_close(struct trace_event_raw_sys_exit* ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;

	u64 *start_time = bpf_map_lookup_elem(&start, &tid);
	if (start_time == 0) {
			return 0;
	}

	u64 delta = bpf_ktime_get_ns() - *start_time;
	delta /= 1000;
	u32 pid = pid_tgid >> 32;

	struct hist *histp = bpf_map_lookup_or_try_init(&hists, &pid, &zero);
	if (!histp) {
		bpf_map_delete_elem(&start, &tid);
		return 0;
	}

	if (!histp->comm[0]) {
		bpf_get_current_comm(&histp->comm, sizeof(histp->comm));
	}

	u64 slot = log2l(delta);
	if (slot >= MAX_SLOTS) {
		slot = MAX_SLOTS - 1;
	}
	__sync_fetch_and_add(&histp->slots[slot], 1);
	bpf_map_delete_elem(&start, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
