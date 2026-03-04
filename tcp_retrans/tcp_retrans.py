#!/usr/bin/env python3

"""
tcp_retrans - Trace TCP retransmission
"""

from bcc import BPF
import socket
import struct

b = BPF(src_file="tcp_retrans.c")
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

print(f"{'PID':<8} {'COMM':<16} {'LADDR':<16} {'DADDR':<16} {'DPORT':<11}")
print("-" * 70)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    l_ip_address = socket.inet_ntoa(struct.pack("=I", event.laddr))
    d_ip_address = socket.inet_ntoa(struct.pack("=I", event.daddr))

    print((
        f"{event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} "
        f"{l_ip_address:<16} {d_ip_address:<16} {event.dport:<11}"
    ))

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
