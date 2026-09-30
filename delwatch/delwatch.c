//
// Crated by Javid Rzayev 9/30/2026
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"

char _license[] SEC("license") = "Dual MIT/GPL";

struct parm {
	__u32 enabled;
	__u32 target_uid;
	__u32 match_all_users;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct parm);
	__uint(max_entries, 1);
} parm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} counter_map SEC(".maps");

SEC("fentry/do_unlinkat")
int do_unlinkat_audit(void *ctx) {
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = (__u32)uid_gid;
	__u32 key = 0;

	struct parm *curr = bpf_map_lookup_elem(&parm_map, &key);

	if (curr == NULL || curr->enabled == 0) {
		return 0;
	}

	__u64 seen = 0;
	__u64 match = 0;
	__u64 skipped = 0;

	if (curr->match_all_users == 1) {
		seen = 1;
		match = 1;
	} else if (curr->target_uid == uid) {
		seen = 1;
		match = 1;
	} else {
		seen = 1;
		skipped = 1;
	}

	__u32 first = 0;
	__u64 *seen_count = bpf_map_lookup_elem(&counter_map, &first);
	if (seen_count && seen == 1) {
		__sync_fetch_and_add(seen_count, 1);
	}

	__u32 second = 1;
	__u64 *match_count = bpf_map_lookup_elem(&counter_map, &second);
	if (match_count && match == 1) {
		__sync_fetch_and_add(match_count, 1);
	}

	__u32 third = 2;
	__u64 *skipped_count = bpf_map_lookup_elem(&counter_map, &third);
	if (skipped_count && skipped == 1) {
		__sync_fetch_and_add(skipped_count, 1);
	}


	return 0;
}




