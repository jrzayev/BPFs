#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct pid_info_t {
  u64 start_ts;
  char comm[TASK_COMM_LEN];
  char fname[DNAME_INLINE_LEN];
};

struct output_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u64 latency_us;
  char fname[DNAME_INLINE_LEN];
};

BPF_HASH(stats, u64, struct pid_info_t);
BPF_PERF_OUTPUT(events);

int kprobe__vfs_read(struct pt_regs *ctx, struct file *file)
{
  struct pid_info_t info = {};
  u64 tid = bpf_get_current_pid_tgid();

  info.start_ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&info.comm, sizeof(info.comm));

  bpf_probe_read_kernel(info.fname, sizeof(info.fname), file->f_path.dentry->d_iname);

  stats.update(&tid, &info);
  return 0;
}

int kretprobe__vfs_read(struct pt_regs *ctx)
{
  u64 tid = bpf_get_current_pid_tgid();
  struct pid_info_t *info = stats.lookup(&tid);
  if (info == 0)
    return 0;

  u64 curr_latency = (bpf_ktime_get_ns() - info->start_ts) / 1000;

  if (curr_latency < 100) {
    stats.delete(&tid);
    return 0;
  }

  struct output_t output = {};
  output.pid = tid >> 32;
  output.latency_us = curr_latency;

  __builtin_memcpy(output.comm, info->comm, sizeof(output.comm));
  __builtin_memcpy(output.fname, info->fname, sizeof(output.fname));

  events.perf_submit(ctx, &output, sizeof(output));

  stats.delete(&tid);

  return 0;
}
