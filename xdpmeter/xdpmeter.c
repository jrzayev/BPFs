//
// Created by jr-free on 10/1/26.
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_endian.h"

char _license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800

struct info {
	__u64 packets;
	__u64 bytes;
};

// 0 - TCP
// 1 - UDP
// 2 - ICMP
// 3 - OTHER
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct info);
} proto_map SEC(".maps");

SEC("xdp")
int xdp_proto_count(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	__u64 bytes = data_end - data;
	__u32 key;

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		key = 3;
	} else {
		struct iphdr *iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end) {
			return XDP_PASS;
		}
		__u8 proto = iph->protocol;
		if (proto == IPPROTO_TCP) {
			key = 0;
		} else if (proto == IPPROTO_UDP) {
			key = 1;
		} else if (proto == IPPROTO_ICMP) {
			key = 2;
		} else {
			key = 3;
		}
	}
	
	struct info *curr = bpf_map_lookup_elem(&proto_map, &key);
	if (curr) {
		__sync_fetch_and_add(&curr->packets, 1);
		__sync_fetch_and_add(&curr->bytes, bytes);
	}
	return XDP_PASS;
}
