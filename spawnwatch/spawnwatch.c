//
// Created by jr-free on 9/30/26.
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include <linux/errno.h>

#define MAX_TRACKED_PIDS 8
char _license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TRACKED_PIDS);
	__type(key, __u32);
	__type(value, __u64);
} child_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost_count SEC(".maps");

SEC("kprobe/kernel_clone")
int trace_kernel_clone(void *ctx) {
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	__u64 *count = bpf_map_lookup_elem(&child_count, &pid);

	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 init = 1;
		int status = bpf_map_update_elem(&child_count, &pid, &init, BPF_NOEXIST);
		if (status == -E2BIG) {
			__u32 key = 0;
			__u64 *err_count = bpf_map_lookup_elem(&lost_count, &key);
			if (err_count == NULL) { return 0; }
			__sync_fetch_and_add(err_count, 1);
		} 

		if (status == -EEXIST) {
			count = bpf_map_lookup_elem(&child_count, &pid);
			if (count) {
				__sync_fetch_and_add(count, 1);
			}
		}
	}

	return 0;
}
