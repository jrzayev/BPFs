#include <linux/fs.h>

BPF_PERCPU_ARRAY(io_stats, u64, 4);

int kretprobe__vfs_read(struct pt_regs *ctx) {
  u32 index = 0;
  u64 *val = io_stats.lookup(&index);
  long ret = PT_REGS_RC(ctx);
  if (val == 0 || ret < 0)
    return 0;

  *val += ret;
  return 0;
}

int kretprobe__vfs_write(struct pt_regs *ctx) {
  u32 index = 1;
  u64 *val = io_stats.lookup(&index);
  long ret = PT_REGS_RC(ctx);
  if (val == 0 || ret < 0)
    return 0;

  *val += ret;
  return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
  u64 bytes = args->nr_sector * 512;
  u32 index = 0;

  if (args->rwbs[0] == 'R') {
    index = 2;
  } else if (args->rwbs[0] == 'W') {
    index = 3;
  } else {
    return 0;
  }

  u64 *val = io_stats.lookup(&index);
  if (val != 0) {
    *val += bytes;
  }

  return 0;
}
