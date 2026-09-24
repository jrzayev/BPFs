//
// Created by jr-free on 9/24/26.
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} ports_map SEC(".maps");

SEC("sk_lookup")
int port_forward_lookup_echo_dispatch(struct bpf_sk_lookup *ctx) {
    if (ctx->protocol != IPPROTO_TCP) {
        return SK_PASS;
    }

    struct bpf_sock *sk;
    const __u32 port = ctx->local_port;
    sk = bpf_map_lookup_elem(&ports_map, &port);
    if (sk == NULL) {
        return SK_PASS;
    }

    const long err = bpf_sk_assign(ctx, sk, 0);
    if (err) {
        bpf_printk("sk_assign failed: %ld", err);
    }

    bpf_sk_release(sk);
    return SK_PASS;
}
