//
// Created by Javid Rzayev on 17.08.26.
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} ipv4_black_list SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct in6_addr);
    __type(value, __u32);
} ipv6_black_list SEC(".maps");


SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
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
        if (bpf_map_lookup_elem(&ipv4_black_list, &source_addr) != NULL)
            return XDP_DROP;
        return XDP_PASS;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        struct in6_addr source_addr = ip6h->saddr;
        if (bpf_map_lookup_elem(&ipv6_black_list, &source_addr) != NULL)
            return XDP_DROP;
        return XDP_PASS;
    }



    return XDP_PASS;
}