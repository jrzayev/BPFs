#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u32 caddr;
  u16 cport;
  u16 lport;
};

BPF_PERF_OUTPUT(events);

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
  if (sk == NULL)
    return 0;
  struct output_t output = {};
  output.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&output.comm, sizeof(output.comm));
  u16 cport = sk->__sk_common.skc_dport;
  output.cport = ntohs(cport);
  output.caddr = sk->__sk_common.skc_daddr;
  output.lport = sk->__sk_common.skc_num;
  events.perf_submit(ctx, &output, sizeof(output));
  return 0;
}
