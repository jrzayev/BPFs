#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>

struct output_t {
  u16 lport;
  u32 cur_qlen;
  u32 max_qlen;
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_v4_syn_recv_sock(struct pt_regs *ctx, const struct sock *sk) {
  if (sk->sk_ack_backlog <= sk->sk_max_ack_backlog)
    return 0;
  struct output_t output = {};
  output.lport = sk->__sk_common.skc_num;
  output.cur_qlen = sk->sk_ack_backlog;
  output.max_qlen = sk->sk_max_ack_backlog;
  events.perf_submit(ctx, &output, sizeof(output));
  return 0;
}
