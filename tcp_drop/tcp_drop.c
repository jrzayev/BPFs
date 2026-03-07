#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u32 saddr;
  u32 daddr;
  u16 dport;
  u16 state;
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

TRACEPOINT_PROBE(skb, kfree_skb) {
  struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
  struct sock *sk = skb->sk;
  if (sk == NULL)
    return 0;

  struct output_t data = {};
  struct output_t *output = connect_start.lookup(&sk);
  if (output != 0) {
    data.pid = output->pid;
    __builtin_memcpy(&data.comm, output->comm, sizeof(data.comm));
    connect_start.delete(&sk);
  } else {
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
  }

  u16 dport = sk->__sk_common.skc_dport;
  data.dport = ntohs(dport);
  data.daddr = sk->__sk_common.skc_daddr;
  data.saddr = sk->__sk_common.skc_rcv_saddr;
  data.state = sk->__sk_common.skc_state;
  events.perf_submit(args, &data, sizeof(data));
  return 0;
}
