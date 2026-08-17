//
// Created by Javid Rzayev on 17.08.26.
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define ETH_ALEN 6
#define MAX_BACKENDS 1024
#define MAX_CONNTRACK 65536

struct backend
{
    __u32 ip;
};

struct config
{
    __u32 vip;
    __u32 base;
    __u32 count;
    __u16 port;
    __u16 pad;
};

struct ct_key
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct ct_val
{
    __u32 client_ip;
    __u32 vip;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend);
} backends SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct config);
} configs SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNTRACK);
    __type(key, struct ct_key);
    __type(value, struct ct_val);
} conntrack SEC(".maps");

static __always_inline void csum_replace4(__u16 *sum, __u32 from, __u32 to)
{
    __u32 tmp = (~(*sum)) & 0xffff;
    tmp += (~from) & 0xffff;
    tmp += (~from >> 16) & 0xffff;
    tmp += to & 0xffff;
    tmp += (to >> 16) & 0xffff;
    tmp = (tmp & 0xffff) + (tmp >> 16);
    tmp = (tmp & 0xffff) + (tmp >> 16);
    *sum = ~tmp;
}

SEC("xdp")
int xdp_load_balance(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u8 proto = iph->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return XDP_PASS;

    void *l4 = (void *)iph + ihl;
    __u16 *sport, *dport, *l4_csum;

    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) > data_end)
            return XDP_PASS;
        sport = &th->source;
        dport = &th->dest;
        l4_csum = &th->check;
    } else
    {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) > data_end)
            return XDP_PASS;
        sport = &uh->source;
        dport = &uh->dest;
        l4_csum = &uh->check;
    }

    __u32 old_saddr = iph->saddr;
    __u32 old_daddr = iph->daddr;
    __u32 new_saddr, new_daddr;

    struct config *cfg = bpf_map_lookup_elem(&configs, &old_daddr);
    if (cfg != NULL && cfg->port == *dport && cfg->count > 0)
    {
        __u32 hash = bpf_ntohl(old_saddr) ^ bpf_ntohs(*sport);
        __u32 index = cfg->base + (hash % cfg->count);

        struct backend *be = bpf_map_lookup_elem(&backends, &index);
        if (be == NULL)
            return XDP_PASS;

        struct ct_key key = {};
        key.saddr = be->ip;
        key.daddr = old_daddr;
        key.sport = *dport;
        key.dport = *sport;
        key.proto = proto;

        struct ct_val val = {};
        val.client_ip = old_saddr;
        val.vip = old_daddr;

        if (bpf_map_update_elem(&conntrack, &key, &val, BPF_ANY) != 0)
            return XDP_PASS;

        new_saddr = old_daddr;
        new_daddr = be->ip;
    } else
    {
        struct ct_key key = {};
        key.saddr = old_saddr;
        key.daddr = old_daddr;
        key.sport = *sport;
        key.dport = *dport;
        key.proto = proto;

        struct ct_val *val = bpf_map_lookup_elem(&conntrack, &key);
        if (val == NULL)
            return XDP_PASS;

        new_saddr = val->vip;
        new_daddr = val->client_ip;
    }

    iph->saddr = new_saddr;
    iph->daddr = new_daddr;
    csum_replace4(&iph->check, old_saddr, new_saddr);
    csum_replace4(&iph->check, old_daddr, new_daddr);

    if (proto == IPPROTO_TCP || *l4_csum != 0)
    {
        csum_replace4(l4_csum, old_saddr, new_saddr);
        csum_replace4(l4_csum, old_daddr, new_daddr);
        if (proto == IPPROTO_UDP && *l4_csum == 0)
            *l4_csum = 0xffff;
    }

    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    return XDP_TX;
}
