//
// Created by Javid Rzayev on 10/1/26.
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_endian.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_tracing.h"
#include <linux/errno.h>


char _license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0

struct info {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct info);
} remote_ips_map SEC(".maps");

SEC("tc")
int tc_stat_ingress(struct __sk_buff *skb) {
	void *data = (void *)(__u64)skb->data;
	void *data_end = (void *)(__u64)skb->data_end;

	struct ethhdr *l2_data;
	struct iphdr *l3_data;


	if (skb->protocol != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}


	l2_data = data;
	if ((void *)(l2_data + 1) > data_end) {
		return TC_ACT_OK;
	}

	l3_data = (struct iphdr *)(l2_data + 1);
	if ((void *)(l3_data + 1) > data_end) {
		return TC_ACT_OK;
	}

	__u32 remote = l3_data->saddr;
	__u64 packet_bytes = skb->len;

	struct info *curr = bpf_map_lookup_elem(&remote_ips_map, &remote);
	if (curr) {
		__sync_fetch_and_add(&curr->rx_packets, 1);
		__sync_fetch_and_add(&curr->rx_bytes, packet_bytes);
	} else {
		struct info new = {};
		new.rx_packets = 1;
		new.rx_bytes = packet_bytes;
		int status = bpf_map_update_elem(&remote_ips_map, &remote, &new, BPF_NOEXIST);
		if (status == -EEXIST) {
			curr = bpf_map_lookup_elem(&remote_ips_map, &remote);
			if (curr) {
				__sync_fetch_and_add(&curr->rx_packets, 1);
				__sync_fetch_and_add(&curr->rx_bytes, packet_bytes);
			}
		} else {
			return TC_ACT_OK;
		}
	}

	return TC_ACT_OK;
}

SEC("tc")
int tc_stat_egress(struct __sk_buff *skb) {
	void *data = (void *)(__u64)skb->data;
	void *data_end = (void *)(__u64)skb->data_end;

	struct ethhdr *l2_data;
	struct iphdr *l3_data;


	if (skb->protocol != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}


	l2_data = data;
	if ((void *)(l2_data + 1) > data_end) {
		return TC_ACT_OK;
	}

	l3_data = (struct iphdr *)(l2_data + 1);
	if ((void *)(l3_data + 1) > data_end) {
		return TC_ACT_OK;
	}

	__u32 remote = l3_data->daddr;
	__u64 packet_bytes = skb->len;

	struct info *curr = bpf_map_lookup_elem(&remote_ips_map, &remote);
	if (curr) {
		__sync_fetch_and_add(&curr->tx_packets, 1);
		__sync_fetch_and_add(&curr->tx_bytes, packet_bytes);
	} else {
		struct info new = {};
		new.tx_packets = 1;
		new.tx_bytes = packet_bytes;
		int status = bpf_map_update_elem(&remote_ips_map, &remote, &new, BPF_NOEXIST);
		if (status == -EEXIST) {
			curr = bpf_map_lookup_elem(&remote_ips_map, &remote);
			if (curr) {
				__sync_fetch_and_add(&curr->tx_packets, 1);
				__sync_fetch_and_add(&curr->tx_bytes, packet_bytes);
			}
		} else {
			return TC_ACT_OK;
		}
	}

	return TC_ACT_OK;
}
