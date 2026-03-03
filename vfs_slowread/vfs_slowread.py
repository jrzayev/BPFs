#!/usr/bin/env python3

"""
vfs_slowread - Trace slow vfs_read calls
"""

from bcc import BPF

b = BPF(src_file="vfs_slowread.c")

print(f"{'PID':<8} {'COMM':<17} {'LATENCY (us)':<14} {'FILE NAME':<20}")
print("-" * 60)

def print_event(cpu, data, size):
    event = b["events"].event(data)

    comm = event.comm.decode('utf-8', 'replace')
    fname = event.fname.decode('utf-8', 'replace')

    print(f"{event.pid:<8} {comm:<17} {event.latency_us:<14} {fname:<20}")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
