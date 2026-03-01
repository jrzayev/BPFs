#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u64 connect_lat_us;
  u32 daddr;
  u16 dport;
  u64 ttfb_us;
  u64 est_ts;
};

BPF_HASH(connect_start, struct sock *, struct output_t);
BPF_HASH(active_conns, struct sock *, struct output_t);
BPF_PERF_OUTPUT(events);


int trace_connect(struct pt_regs *ctx, struct sock *sk) {
  struct output_t output = {};
  output.est_ts = bpf_ktime_get_ns();
  output.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&output.comm, sizeof(output.comm));
  connect_start.update(&sk, &output);
  return 0;
}

int trace_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
  if (state != 1)
    return 0;

  struct output_t *output = connect_start.lookup(&sk);
  if (output == 0)
    return 0;

  u64 curr_ts = bpf_ktime_get_ns();
  u64 delta = curr_ts - output->est_ts;

  output->connect_lat_us = delta / 1000;
  output->est_ts = curr_ts;
  u16 dport = sk->__sk_common.skc_dport;
  output->dport = ntohs(dport);
  output->daddr = sk->__sk_common.skc_daddr;
  active_conns.update(&sk, output);
  connect_start.delete(&sk);
  return 0;
}

int trace_rcv_data(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
  struct output_t *output = active_conns.lookup(&sk);
  if (output == 0)
    return 0;

  u64 ttfb_ns = bpf_ktime_get_ns() - output->est_ts;
  output->ttfb_us = ttfb_ns / 1000;
  events.perf_submit(ctx, output, sizeof(*output));
  active_conns.delete(&sk);
  return 0;
}
