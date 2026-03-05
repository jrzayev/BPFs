#!/usr/bin/env python3

"""
tcp_accept - Trace TCP Established connections
"""

from bcc import BPF
import socket
import struct

b = BPF(src_file="tcp_accept.c")

print(f"{'PID':<8} {'COMM':<16} {'CADDR':<16} {'CPORT':<11} {'LPORT':<11}")
print("-" * 65)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    c_ip_address = socket.inet_ntoa(struct.pack("=I", event.caddr))

    print((
        f"{event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} "
        f"{c_ip_address:<16} {event.cport:<11} {event.lport:<11}"
    ))

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
