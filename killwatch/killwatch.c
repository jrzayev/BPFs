//
// Created by jr-free on 9/30/26.
//
//go:build ignore


#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_endian.h"

char _license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} kill_count SEC(".maps");

SEC("kprobe/__x64_sys_kill")
int sys_kill_count(struct pt_regs *ctx) {
  __u32 key = 0;

  __u64 *count = bpf_map_lookup_elem(&kill_count, &key);
  if (count) {
    __sync_fetch_and_add(count, 1);
  } else {
    __u64 init = 1;
    bpf_map_update_elem(&kill_count, &key, &init, BPF_ANY);
  }

  return 0;
}

