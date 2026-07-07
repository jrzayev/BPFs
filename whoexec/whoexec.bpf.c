#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "whoexec.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("tp/sched/sched_process_exec")
int start_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned fname_off;
	struct event *e;
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->uid = bpf_get_current_uid_gid();
	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
