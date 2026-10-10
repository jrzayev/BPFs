//
// Crated by Javid Rzayev 10/5/2026
//
//go:build ignore

#include "../common/vmlinux.h"
#include "../common/bpf_helpers.h"
#include "../common/bpf_tracing.h"

char _license[] SEC("license") = "Dual MIT/GPL";

#define GOID_OFFSET 0x98
#define TASK_DEAD 0x80
#define G_RUNNABLE 1
#define G_RUNNING  2
#define G_SYSCALL  3
#define G_WAITING  4
#define G_DEAD     6
#define G_IDLE     0

struct event {
  __u32 pid;
  __u32 tid;
  __u32 new_state;
  __u32 old_state;
  __u64 goid;
  __u64 ts;
};

struct goid_cur {
  __u32 curr_state;
  __u64 ts;
};

struct goid_off_val {
  __u64 runnable;
  __u64 waiting;
  __u64 kernel_off;
};

struct goid_summary {
  __u32 pid;
  __u32 _pad;
  __u64 goid;
  __u64 on;
  __u64 runnable;
  __u64 waiting;
  __u64 kernel_off;
};

const struct event *unused __attribute__((unused));
const struct goid_cur *unused_curr __attribute__((unused));
const struct goid_off_val *unused_off_val __attribute__((unused));
const struct goid_summary *unused_summary __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} summaries SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} tid_to_goid SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} userspace_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} tid_last_switch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} on_ns SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} off_ns SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);
  __type(value, __u64);
} goid_on_ns SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);
  __type(value, struct goid_cur);
} goid_state SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);
  __type(value, struct goid_off_val);
} goid_off SEC(".maps");

static __always_inline void charge_on(__u32 tid, __u64 ts)
{
  __u64 *last_ts = bpf_map_lookup_elem(&tid_last_switch, &tid);
  if (last_ts) {
    __u64 delta = ts - *last_ts;

    __u64 *total = bpf_map_lookup_elem(&on_ns, &tid);
    if (total) {
      *total += delta;
    } else {
      bpf_map_update_elem(&on_ns, &tid, &delta, BPF_ANY);
    }

    __u64 owner = 0;
    __u64 *curr_goid = bpf_map_lookup_elem(&tid_to_goid, &tid);
    if (curr_goid) {
      owner = *curr_goid;
    }

    __u64 *goid_total = bpf_map_lookup_elem(&goid_on_ns, &owner);
    if (goid_total) {
      __sync_fetch_and_add(goid_total, delta);
    } else {
      bpf_map_update_elem(&goid_on_ns, &owner, &delta, BPF_ANY);
    }
  }
  bpf_map_update_elem(&tid_last_switch, &tid, &ts, BPF_ANY);
}

static __always_inline void track_go_state(__u64 goid, __u32 new_state, __u64 ts)
{
  struct goid_cur *cur = bpf_map_lookup_elem(&goid_state, &goid);
  if (cur) {
    __u64 delta = ts - cur->ts;
    __u32 prev = cur->curr_state;

    if (prev == G_RUNNABLE || prev == G_WAITING) {
      struct goid_off_val *off = bpf_map_lookup_elem(&goid_off, &goid);
      if (off) {
        if (prev == G_RUNNABLE) {
          __sync_fetch_and_add(&off->runnable, delta);
        } else {
          __sync_fetch_and_add(&off->waiting, delta);
        }
      } else {
        struct goid_off_val init = {};
        if (prev == G_RUNNABLE) {
          init.runnable = delta;
        } else {
          init.waiting = delta;
        }
        bpf_map_update_elem(&goid_off, &goid, &init, BPF_ANY);
      }
    }
  }
  struct goid_cur next;
  __builtin_memset(&next, 0, sizeof(next));
  next.curr_state = new_state;
  next.ts = ts;
  bpf_map_update_elem(&goid_state, &goid, &next, BPF_ANY);
}

static __always_inline void charge_kernel_off(__u32 tid, __u64 delta)
{
  __u64 *curr_goid = bpf_map_lookup_elem(&tid_to_goid, &tid);
  if (!curr_goid) {
    return;
  }
  __u64 goid = *curr_goid;

  struct goid_off_val *off = bpf_map_lookup_elem(&goid_off, &goid);
  if (off) {
    __sync_fetch_and_add(&off->kernel_off, delta);
  } else {
    struct goid_off_val init = {};
    init.kernel_off = delta;
    bpf_map_update_elem(&goid_off, &goid, &init, BPF_ANY);
  }
}

static __always_inline void finish_goroutine(__u32 pid, __u64 goid)
{
  struct goid_summary *s = bpf_ringbuf_reserve(&summaries, sizeof(*s), 0);
  if (s) {
    __builtin_memset(s, 0, sizeof(*s));
    s->pid = pid;
    s->goid = goid;

    __u64 *on = bpf_map_lookup_elem(&goid_on_ns, &goid);
    if (on) {
      s->on = *on;
    }
    struct goid_off_val *off = bpf_map_lookup_elem(&goid_off, &goid);
    if (off) {
      s->runnable = off->runnable;
      s->waiting = off->waiting;
      s->kernel_off = off->kernel_off;
    }
    bpf_ringbuf_submit(s, 0);
  }

  bpf_map_delete_elem(&goid_state, &goid);
  bpf_map_delete_elem(&goid_on_ns, &goid);
  bpf_map_delete_elem(&goid_off, &goid);
}

SEC("uprobe")
int uprobe_runtime_casgstatus(struct pt_regs *ctx)
{
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;
  __u32 pid = pid_tgid >> 32;

  __u32 key = 0;
  __u32 *userspace_pid = bpf_map_lookup_elem(&userspace_config, &key);
  if (!userspace_pid || *userspace_pid == 0 || *userspace_pid != pid) {
    return 0;
  }

  __u64 goid;
  __u64 ts = bpf_ktime_get_ns();
  __u32 new_state = ctx->cx;
  __u32 old_state = ctx->bx;
  void *gp = (void *)ctx->ax;
  struct event *data;

  long res = bpf_probe_read_user(&goid, sizeof(goid), gp + GOID_OFFSET);
  if (res != 0) {
    return 0;
  }
  if (goid != 0 && old_state != G_IDLE && old_state != G_DEAD) {
    track_go_state(goid, new_state, ts);
  }

  if (new_state == G_RUNNING) {
    charge_on(tid, ts);
    bpf_map_update_elem(&tid_to_goid, &tid, &goid, BPF_ANY);
  } else {
    if (new_state != G_SYSCALL) {
      __u64 *curr_goid = bpf_map_lookup_elem(&tid_to_goid, &tid);
      if (curr_goid != NULL && *curr_goid == goid) {
        charge_on(tid, ts);
        bpf_map_delete_elem(&tid_to_goid, &tid);
      }
    }
  }

  if (new_state == G_DEAD && goid != 0 && old_state != G_IDLE) {
    finish_goroutine(pid, goid);
  }

  data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
  if (!data) {
    return 0;
  }

  data->pid = pid;
  data->tid = tid;
  data->goid = goid;
  data->new_state = new_state;
  data->old_state = old_state;
  data->ts = ts;
  bpf_ringbuf_submit(data, 0);

  return 0;
}

SEC("tp_btf/sched_switch")
int tp_btf_sched_switch(u64 *ctx) {
  struct task_struct *prev = (struct task_struct *)ctx[1];
  struct task_struct *next = (struct task_struct *)ctx[2];
  __u32 prev_pid = prev->pid;
  __u32 next_pid = next->pid;
  __u32 prev_tgid = prev->tgid;
  __u32 next_tgid = next->tgid;
  __u32 prev_state = prev->__state;
  __u64 ts = bpf_ktime_get_ns();

  __u32 key = 0;
  __u32 *userspace_pid = bpf_map_lookup_elem(&userspace_config, &key);
  if (!userspace_pid || *userspace_pid == 0) {
    return 0;
  }

  if (prev_tgid == *userspace_pid) {
    if (prev_state & TASK_DEAD) {
      bpf_map_delete_elem(&tid_last_switch, &prev_pid);
      bpf_map_delete_elem(&on_ns, &prev_pid);
      bpf_map_delete_elem(&off_ns, &prev_pid);
      bpf_map_delete_elem(&tid_to_goid, &prev_pid);
    } else {
      charge_on(prev_pid, ts);
    }
  }

  if (next_tgid == *userspace_pid) {
    __u64 *last_ts = bpf_map_lookup_elem(&tid_last_switch, &next_pid);
    if (last_ts) {
      __u64 delta = ts - *last_ts;
      __u64 *total = bpf_map_lookup_elem(&off_ns, &next_pid);
      if (total) {
        *total += delta;
      } else {
        bpf_map_update_elem(&off_ns, &next_pid, &delta, BPF_ANY);
      }
      charge_kernel_off(next_pid, delta);
    }
    bpf_map_update_elem(&tid_last_switch, &next_pid, &ts, BPF_ANY);
  }

  return 0;
}
