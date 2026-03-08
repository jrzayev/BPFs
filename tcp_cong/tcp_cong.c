#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/bpf.h>

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u32 daddr;
  u16 dport;
  u8 ca_state;
  u32 cwnd;
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_set_ca_state(struct pt_regs *ctx, struct sock *sk, const u8 ca_state) {
  struct output_t output = {};
  output.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&output.comm, sizeof(output.comm));
  u16 dport = sk->__sk_common.skc_dport;
  output.dport = ntohs(dport);
  output.daddr = sk->__sk_common.skc_daddr;
  output.ca_state = ca_state;
  struct tcp_sock *tp = (struct tcp_sock *)sk;
  output.cwnd = tp->snd_cwnd;
  events.perf_submit(ctx, &output, sizeof(output));
  return 0;
}
