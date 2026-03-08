#!/usr/bin/env python3

"""
tcp_cong - TCP Congestion Tracker

You can find what means each state and more information in here:
https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h#L194

ToDo:
- Add specific pid and comm
"""

from bcc import BPF
import socket
import struct

b = BPF(src_file="tcp_cong.c")

print(f"{'PID':<8} {'COMM':<16} {'DADDR':<15} {'DPORT':<10} {'CA_STATE':<10} {'CWND':<10}")
print("-" * 68)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    d_ip_address = socket.inet_ntoa(struct.pack("=I", event.daddr))

    print((
        f"{event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} "
        f"{d_ip_address:<15} {event.dport:<10} {event.ca_state:<10} {event.cwnd:<10}"
    ))

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
