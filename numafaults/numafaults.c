#include <linux/fs.h>

typedef struct {
  char comm[TASK_COMM_LEN];
  u64 local_faults;
  u64 remote_faults;
} faults_t;

BPF_PERCPU_HASH(numa_faults, u32, faults_t, 10240);

int kprobe__task_numa_fault(struct pt_regs *ctx, int last_cpupid, int mem_node, int pages, int flags) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  int cpu_node = bpf_get_numa_node_id();

  faults_t faults = {};
  faults_t *tsp_faults = numa_faults.lookup_or_try_init(&pid, &faults);
  if (tsp_faults == 0)
    return 0;

  bpf_get_current_comm(tsp_faults->comm, sizeof(tsp_faults->comm));

  if (mem_node == cpu_node)
    tsp_faults->local_faults += 1;
  else
    tsp_faults->remote_faults += 1;

  return 0;
}
