#!/usr/bin/env python3

"""
tcp_drop - TCP Drop Tracker

You can find what means each state in here:
https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h
"""

from bcc import BPF
import socket
import struct

b = BPF(src_file="tcp_drop.c")
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

print(f"{'PID':<8} {'COMM':<16} {'SADDR':<15} {'DADDR':<15} {'DPORT':<10} {'STATE':<8}")
print("-" * 75)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    s_ip_address = socket.inet_ntoa(struct.pack("=I", event.saddr))
    d_ip_address = socket.inet_ntoa(struct.pack("=I", event.daddr))

    print((
        f"{event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} "
        f"{s_ip_address:<15} {d_ip_address:<15} {event.dport:<10} {event.state:<8}"
    ))

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
