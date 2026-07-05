#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES	10240
#define MAX_SLOTS	26


struct hist {
  __u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
};

#endif
