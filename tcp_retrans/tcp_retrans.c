#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u32 laddr;
  u32 daddr;
  u16 dport;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(connect_start, struct sock *, struct output_t);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
  struct output_t output = {};
  output.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&output.comm, sizeof(output.comm));
  connect_start.update(&sk, &output);
  return 0;
}

int kprobe__tcp_retransmit_skb(struct pt_regs *ctx, struct sock *sk) {
  struct output_t *output = connect_start.lookup(&sk);
  if (output == 0)
    return 0;
  u16 dport = sk->__sk_common.skc_dport;
  output->dport = ntohs(dport);
  output->daddr = sk->__sk_common.skc_daddr;
  output->laddr = sk->__sk_common.skc_rcv_saddr;
  events.perf_submit(ctx, output, sizeof(*output));
  connect_start.delete(&sk);
  return 0;
}
