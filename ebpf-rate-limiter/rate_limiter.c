//
// Created by Javid Rzayev on 17.08.26.
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP           0x0800
#define WINDOW_NS          1000000000ULL
#define DEFAULT_RATE_LIMIT 100

struct packet_metadata
{
    __u64 window_start;
    __u32 packets;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct packet_metadata);
} metadata SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} rate_limit SEC(".maps");

SEC("xdp")
int xdp_rate_limit(struct xdp_md *ctx)
{
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        __u32 source_addr = iph->saddr;
        __u32 curr_rate_limit = DEFAULT_RATE_LIMIT;
        __u32 *custom_limit = bpf_map_lookup_elem(&rate_limit, &source_addr);
        if (custom_limit) {
            curr_rate_limit = *custom_limit;
        }

        struct packet_metadata *info = bpf_map_lookup_elem(&metadata, &source_addr);
        if (info != NULL)
        {
            __u64 now = bpf_ktime_get_ns();
            if (now - info->window_start > WINDOW_NS)
            {
                info->window_start = now;
                info->packets = 0;
            }

            if (info->packets >= curr_rate_limit)
                return XDP_DROP;

            info->packets++;
        } else
        {
            struct packet_metadata new_info = {};
            new_info.window_start = bpf_ktime_get_ns();
            new_info.packets = 1;
            bpf_map_update_elem(&metadata, &source_addr, &new_info, BPF_ANY);
        }
    }

    return XDP_PASS;
}
