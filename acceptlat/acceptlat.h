#ifndef __ACCEPTLAT_H
#define __ACCEPTLAT_H

#define TASK_COMM_LEN	16

struct event {
	__u64 delta_us;
	char comm[TASK_COMM_LEN];
  __u16 sport;
	__u16 dport;
  __u32 tgid;
  union {
      __u32 saddr_v4;
      __u8 saddr_v6[16];
  };
  union {
      __u32 daddr_v4;
      __u8 daddr_v6[16];
  };
  __u16 af;
};

#endif
