#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/bpf.h>

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u16 lport;
  u16 dport;
  int old_state;
  int new_state;
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

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
  if (sk == NULL)
    return 0;
  struct output_t data = {};
  struct output_t *output = connect_start.lookup(&sk);
  if (output == 0) {
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    connect_start.update(&sk, &data);
  }
  return 0;
}

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
  struct output_t data = {};
  struct output_t *output = connect_start.lookup(&sk);
  if (output != 0) {
    data.pid = output->pid;
    __builtin_memcpy(&data.comm, output->comm, sizeof(data.comm));
  } else {
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
  }

  u16 dport = sk->__sk_common.skc_dport;
  data.dport = ntohs(dport);
  data.lport = sk->__sk_common.skc_num;
  data.old_state = sk->__sk_common.skc_state;
  data.new_state = state;
  events.perf_submit(ctx, &data, sizeof(data));

  if (state == 7)
    connect_start.delete(&sk);

  return 0;
}
