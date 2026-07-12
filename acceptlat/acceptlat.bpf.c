#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "acceptlat.h"


char LICENSE[] SEC("license") = "GPL";


#define AF_INET 2
#define AF_INET6 10


const volatile __u64 target_sport = 0;
const volatile __u64 target_min_us = 0;
const volatile pid_t target_tgid = 0;


struct conn_data {
  __u16 sport;
  __u16 dport;
  __u64 start_ts;
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct sock *);
  __type(value, struct conn_data);
} start SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
  if (ctx->protocol != IPPROTO_TCP)
		return 0;

	struct sock *sk = (struct sock *)ctx->skaddr;
  __u16 sport = ctx->sport;

  if (target_sport != 0 && target_sport != sport)
		return 0;

  if (ctx->oldstate == TCP_SYN_RECV && ctx->newstate == TCP_ESTABLISHED) {
    struct conn_data conn_data = {};
    __u16 dport = ctx->dport;
    conn_data.sport = sport;
  	conn_data.dport = dport;
    conn_data.start_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &sk, &conn_data, 0);
  }

	return 0;
}


SEC("fexit/inet_csk_accept")
int BPF_PROG(fexit_inet_csk_accept, struct sock *sk,
  struct proto_accept_arg *arg, struct sock *retval)
{
	struct conn_data *conn_data;
	struct event event = {};
	s64 delta_ts;
	u64 curr_ts;
	u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (!retval)
		return 0;

	conn_data = bpf_map_lookup_elem(&start, &retval);
	if (!conn_data)
		return 0;

	if (target_tgid != 0 && target_tgid != tgid)
		goto bye;

	curr_ts = bpf_ktime_get_ns();
	delta_ts = (s64)(curr_ts - conn_data->start_ts);
	if (delta_ts < 0)
		goto bye;

	event.delta_us = delta_ts / 1000U;
	if (target_min_us != 0 && event.delta_us < target_min_us)
		goto bye;

	event.tgid = tgid;

	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.sport = conn_data->sport;
	event.dport = conn_data->dport;
  event.af = BPF_CORE_READ(retval, __sk_common.skc_family);
	if (event.af == AF_INET) {
		event.saddr_v4 = BPF_CORE_READ(retval, __sk_common.skc_rcv_saddr);
		event.daddr_v4 = BPF_CORE_READ(retval, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&event.saddr_v6, retval,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.daddr_v6, retval,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			&event, sizeof(event));

bye:
	bpf_map_delete_elem(&start, &retval);
	return 0;
}
