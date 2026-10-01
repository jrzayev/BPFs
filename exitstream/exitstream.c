//
// Created by Javid Rzayev 01/10/2026
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_tracing.h"

char _license[] SEC("license") = "Dual MIT/GPL";

struct event {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u64 ts;
	__u8 comm[16];
};

const struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int trace_sys_exit(void *ctx) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e) {
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&drops, &key);
		if (count == NULL) {
			return 0;
		}
		__sync_fetch_and_add(count, 1);
		return 0;
	}

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;
	e->ts = bpf_ktime_get_ns();

	bpf_ringbuf_submit(e, 0);

	return 0;
}
