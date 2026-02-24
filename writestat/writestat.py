#!/usr/bin/env python3

"""
writestat - Synchronous vs Asynchronous Write Analysis Tool using eBPF

Description:
    This tool traces Virtual File System (VFS) functions (`vfs_write`,
    `vfs_fsync`, `fdatasync`) to separate and measure write operations:

     - ASYNC: Data written to the Linux Page Cache (fast/buffered).
     - SYNC: Data flushed directly to the physical disk (slow/O_SYNC or fsync).

Output:
    Updates every second, showing aggregated statistics: IOPS, throughput (MB/s),
    and latency (AVG_LAT / MAX_LAT in ms) grouped by PID, process name, and write type.
"""

import time
from bcc import BPF

b = BPF(src_file="writestat.c")

b.attach_kprobe(event="vfs_fsync", fn_name="trace_fsync_entry")
b.attach_kprobe(event=b.get_syscall_fnname("fdatasync"), fn_name="trace_fsync_entry")

b.attach_kretprobe(event="vfs_fsync", fn_name="trace_fsync_return")
b.attach_kretprobe(event=b.get_syscall_fnname("fdatasync"), fn_name="trace_fsync_return")


print(f"{'PID':<10} {'COMM':<10} {'TYPE':<10} {'IOPS':<10} {'MB/s':<10} {'AVG_LAT':<10} {'MAX_LAT':<10}")
try:
    while True:
        time.sleep(1)
        stats = b["stats"]
        for k, values in stats.items():
            pid = k.pid
            comm = k.comm.decode('utf-8', 'replace')
            type = "SYNC"
            if k.type == 0:
                type = "ASYNC"
            calls = sum(v.calls for v in values)
            bytes = sum(v.bytes for v in values)
            total_lat = sum(v.total_lat for v in values)
            max_lat = float("-inf")
            for v in values:
                max_lat = max(max_lat, v.max_lat)

            mb_s = bytes / (1024 * 1024)
            avg_lat_ms = (total_lat / calls) / 1000000.0 if calls > 0 else 0
            max_lat_ms = max_lat / 1000000.0

            print(f"{pid:<10} {comm:<10} {type:<10} {calls:<10} {mb_s:<10.2f} {avg_lat_ms:<10.2f} {max_lat_ms:<10.2f}")

        stats.clear()
        print("-" * 74)
except KeyboardInterrupt:
    print("\nTschüss!")
