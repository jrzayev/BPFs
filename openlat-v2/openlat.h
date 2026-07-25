#ifndef __OPENLAT_H
#define __OPENLAT_H

#define MAX_ENTRIES 10240
#define MAX_SLOTS	26
#define TASK_COMM_LEN 16
#define MAX_STARS 40
#define MAX_FILENAME_LEN 127


struct hist {
  __u32 slots[MAX_SLOTS];
  char comm[TASK_COMM_LEN];
};

struct event {
  int pid;
  __u64 delta_us;
  char comm[TASK_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
};


#endif
