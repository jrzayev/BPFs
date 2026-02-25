#!/usr/bin/env python3

"""
ampstat - I/O Amplification Analysis Tool using eBPF

Description:
    This tool traces Virtual File System (VFS) functions (`vfs_read`, `vfs_write`)
    and block layer events (`block:block_rq_complete`) to measure global I/O amplification:

     - LOGICAL: Data requested to be read/written by applications (VFS layer).
     - PHYSICAL: Actual data read/written to the underlying storage device (Block layer).

Output:
    Updates every second, showing global throughput (MB/s) for both logical
    and physical I/O, along with the resulting amplification factor (Physical / Logical).
"""

import time
from bcc import BPF

b = BPF(src_file="ampstat.c")

print(f"{'METRIC':<10} {'LOGICAL (MB/s)':<16} {'PHYSICAL (MB/s)':<17} {'AMPLIFICATION':<15}")
try:
    while True:
        time.sleep(1)
        io_stats = b["io_stats"]

        logical_read = sum(io_stats[0]) / (1024 * 1024)
        logical_write = sum(io_stats[1]) / (1024 * 1024)

        physical_read = sum(io_stats[2]) / (1024 * 1024)
        physical_write = sum(io_stats[3]) / (1024 * 1024)

        amp_read_str = f"{physical_read / logical_read:.2f}x" if logical_read > 0 else "-"
        amp_write_str = f"{physical_write / logical_write:.2f}x" if logical_write > 0 else "-"

        print(f"{'Read':<10} {logical_read:<16.2f} {physical_read:<17.2f} {amp_read_str:<15}")
        print(f"{'Write':<10} {logical_write:<16.2f} {physical_write:<17.2f} {amp_write_str:<15}")

        io_stats.clear()
        print("-" * 60)
except KeyboardInterrupt:
    print("\nTschüss!")
