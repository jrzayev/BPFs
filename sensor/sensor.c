//
// Crated by Javid Rzayev 10/1/2026
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_tracing.h"
#include <linux/errno.h>

#define MAX_TRACKED_PIDS 1024
#define MAX_COMM_LEN 16

char _license[] SEC("license") = "Dual MIT/GPL";

// Alert types
// 0 - ROOT_EXEC
// 1 - ROOT_DELETE
// 2 - ROOT_SPAWN
// 3 - DELETE_LIMIT
// 4 - SPAWN_LIMIT
// 5 - EXEC_LIMIT
struct event {
  __u32 pid;
  __u32 uid;
  __u32 alert_type;
  __u8 comm[MAX_COMM_LEN];
  __u64 ts;
};

struct parm {
  __u32 root; // 0 - root off and 1 - root on
  __u32 status; // 0 - pause and 1 - resume
  __u32 delete_limit;
  __u32 spawn_limit;
  __u32 exec_limit;
};

struct info {
  __u32 delete_count;
  __u32 spawn_count;
  __u32 exec_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct parm);
} parms SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_TRACKED_PIDS);
  __type(key, __u32);
  __type(value, struct info);
} infos SEC(".maps");

// 0 - if lost for spawn non root
// 1 - if lost for delete non root
// 2 - if lost for exec non root
// 3 - if lost for root spawn
// 4 - if lost for root delete
// 5 - if lost for root exec
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 6);
	__type(key, __u32);
	__type(value, __u64);
} losts SEC(".maps");

const struct event *unused __attribute__((unused));

static __always_inline int send_alarm(__u32 pid, __u32 uid, __u32 alert_type, __u32 err_key) {
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->uid = uid;
    e->pid = pid;
    e->ts = bpf_ktime_get_ns();
    e->alert_type = alert_type;
    bpf_ringbuf_submit(e, 0);
  } else {
    __u64 *err_count = bpf_map_lookup_elem(&losts, &err_key);
    if (err_count) {
      __sync_fetch_and_add(err_count, 1);
    }
  }
  return 0;
}

// 0 - spawn
// 1 - delete
// 2 - exec
static __always_inline __u32 get_curr_count(__u32 pid, __u32 func_id) {
  struct info *pid_curr_info = bpf_map_lookup_elem(&infos, &pid);
  __u32 curr_count = 0;
  if (pid_curr_info){
    if (func_id == 0)
      curr_count = __sync_fetch_and_add(&pid_curr_info->spawn_count, 1) + 1;
    if (func_id == 1)
      curr_count = __sync_fetch_and_add(&pid_curr_info->delete_count, 1) + 1;
    if (func_id == 2)
      curr_count = __sync_fetch_and_add(&pid_curr_info->exec_count, 1) + 1;
  } else {
    struct info pid_new_info = {};
    pid_new_info.spawn_count = func_id == 0 ? 1 : 0;
    pid_new_info.delete_count = func_id == 1 ? 1 : 0;
    pid_new_info.exec_count = func_id == 2 ? 1 : 0;
    int status = bpf_map_update_elem(&infos, &pid, &pid_new_info, BPF_NOEXIST);
    if (status == -EEXIST) {
      pid_curr_info = bpf_map_lookup_elem(&infos, &pid);
      if (pid_curr_info) {
        if (func_id == 0)
          curr_count = __sync_fetch_and_add(&pid_curr_info->spawn_count, 1) + 1;
        if (func_id == 1)
          curr_count = __sync_fetch_and_add(&pid_curr_info->delete_count, 1) + 1;
        if (func_id == 2)
          curr_count = __sync_fetch_and_add(&pid_curr_info->exec_count, 1) + 1;
      }
    } else if (status == 0) {
      curr_count = 1;
    }
  }
  return curr_count;
}

SEC("kprobe/kernel_clone")
int sensor_kp_kernel_clone(void *ctx) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 uid_gid = bpf_get_current_uid_gid();
  __u32 uid = (__u32)uid_gid;
  __u32 parm_key = 0;
  __u32 root_error_key = 3;
  __u32 general_error_key = 0;
  __u32 root_alert_type = 2;
  __u32 general_alert_type = 4;

  struct parm *pid_curr_parm = bpf_map_lookup_elem(&parms, &parm_key);
  if (!pid_curr_parm || pid_curr_parm->status == 0) {
    return 0;
  }
  if (pid_curr_parm->root == 1 && uid == 0) {
    send_alarm(pid, uid, root_alert_type, root_error_key);
  }

  __u32 curr_count = get_curr_count(pid, 0);
  if (curr_count == pid_curr_parm->spawn_limit && curr_count != 0) {
    send_alarm(pid, uid, general_alert_type, general_error_key);
  }
  return 0;
}

SEC("fentry/do_unlinkat")
int sensor_fn_do_unlinkat(void *ctx) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 uid_gid = bpf_get_current_uid_gid();
  __u32 uid = (__u32)uid_gid;
  __u32 parm_key = 0;
  __u32 root_error_key = 4;
  __u32 general_error_key = 1;
  __u32 root_alert_type = 1;
  __u32 general_alert_type = 3;

  struct parm *pid_curr_parm = bpf_map_lookup_elem(&parms, &parm_key);
  if (!pid_curr_parm || pid_curr_parm->status == 0) {
    return 0;
  }
  if (pid_curr_parm->root == 1 && uid == 0) {
    send_alarm(pid, uid, root_alert_type, root_error_key);
  }
  __u32 curr_count = get_curr_count(pid, 1);

  if (curr_count == pid_curr_parm->delete_limit && curr_count != 0) {
    send_alarm(pid, uid, general_alert_type, general_error_key);
  }
  return 0;
}

SEC("tp/sched/sched_process_exec")
int sensor_tp_sched_process_exec(void *ctx) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 uid_gid = bpf_get_current_uid_gid();
  __u32 uid = (__u32)uid_gid;
  __u32 parm_key = 0;
  __u32 root_error_key = 5;
  __u32 general_error_key = 2;
  __u32 root_alert_type = 0;
  __u32 general_alert_type = 5;

  struct parm *pid_curr_parm = bpf_map_lookup_elem(&parms, &parm_key);
  if (!pid_curr_parm || pid_curr_parm->status == 0) {
    return 0;
  }
  if (pid_curr_parm->root == 1 && uid == 0) {
    send_alarm(pid, uid, root_alert_type, root_error_key);
  }

  __u32 curr_count = get_curr_count(pid, 2);

  if (curr_count == pid_curr_parm->exec_limit && curr_count != 0) {
    send_alarm(pid, uid, general_alert_type, general_error_key);
  }
  return 0;
}
