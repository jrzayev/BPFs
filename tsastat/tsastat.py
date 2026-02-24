#!/usr/bin/env python3

"""
tsastat - Thread State Analysis Tool using eBPF

Description:
    This tool traces kernel scheduler switches (`sched:sched_switch`) to measure
    time spent by threads in different states.

     - RUN (Runnable)
     - DISK (Uninterruptible)
     - SLEEP (Interruptible)

Output:
    Updates every second, showing cumulative time (in ms) for each active PID.
"""

import time
from bcc import BPF

b = BPF(src_file="tsastat.c")

NS_TO_MS = 1_000_000

print(f"{'PID':<10} {'RUN(ms)':<10} {'SLEEP(ms)':<10} {'DISK(ms)':<10}")
try:
    while True:
        time.sleep(1)
        dist = b["dist"]
        for k, values in dist.items():
            run = sum(v.run_time for v in values) // NS_TO_MS
            sleep = sum(v.sleep_time for v in values) // NS_TO_MS
            disk = sum(v.disk_time for v in values) // NS_TO_MS
            if run or sleep or disk:
                print(f"{k.value:<10d} {run:<10d} {sleep:<10d} {disk:<10d}")
        dist.clear()
        print("-" * 44)
except KeyboardInterrupt:
    print("\nTschüss!")
