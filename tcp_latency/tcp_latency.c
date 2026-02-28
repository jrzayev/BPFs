#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u64 delay_us;
  u32 usage_percent;
  u32 is_tx;
};

BPF_HASH(start_queue, struct sock *, u64);
BPF_HASH(start_tx, struct sk_buff *, u64);
BPF_PERF_OUTPUT(events);

int trace_start_queue(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u64 ts = bpf_ktime_get_ns();
    start_queue.lookup_or_try_init(&sk, &ts);
    return 0;
}

int trace_end_recv(struct pt_regs *ctx, struct sock *sk) {
    u64 *start_ts = start_queue.lookup(&sk);
    if (start_ts == 0)
        return 0;

    u64 delta = bpf_ktime_get_ns() - *start_ts;

    u32 rcv_filled;
    u32 rcv_max;

    bpf_probe_read_kernel(&rcv_filled, sizeof(rcv_filled), &sk->sk_rmem_alloc.counter);
    bpf_probe_read_kernel(&rcv_max, sizeof(rcv_max), &sk->sk_rcvbuf);

    if (rcv_max > 0) {
        u32 usage_percent = (rcv_filled * 100) / rcv_max;
        if (usage_percent > 80 && delta > 1000000) {
          struct output_t output = {};
          output.pid = bpf_get_current_pid_tgid() >> 32;
          bpf_get_current_comm(&output.comm, sizeof(output.comm));
          output.delay_us = delta / 1000;
          output.usage_percent = usage_percent;
          output.is_tx = 0;
          events.perf_submit(ctx, &output, sizeof(output));
        }
    }

    start_queue.delete(&sk);
    return 0;
}

int trace_tx_start(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
  u64 ts = bpf_ktime_get_ns();
  start_tx.update(&skb, &ts);
  return 0;
}

int trace_tx_end(struct pt_regs *ctx, struct sk_buff *skb) {
  u64 *start_tx_val = start_tx.lookup(&skb);
  if (start_tx_val == 0)
    return 0;

  u64 delta = bpf_ktime_get_ns() - *start_tx_val;
  start_tx.delete(&skb);
  if (delta > 1000000) {
    struct output_t output = {};
    output.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&output.comm, sizeof(output.comm));
    output.delay_us = delta / 1000;
    output.usage_percent = 0;
    output.is_tx = 1;
    events.perf_submit(ctx, &output, sizeof(output));
  }

  return 0;
}
