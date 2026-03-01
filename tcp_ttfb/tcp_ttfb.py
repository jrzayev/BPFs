#!/usr/bin/env python3

"""
tcp_ttfb - TCP Handshake and TTFB Profiler

Description:
    Measures the latency of the TCP 3-way handshake (connect latency)
    and the Time-To-First-Byte (TTFB) for active outbound connections.
    Ignores passive incoming (server) connections.

Output:
    Real-time events showing PID, command name, destination IP/port,
    handshake duration, and TTFB in microseconds for every new connection.
"""

from bcc import BPF
import time
import socket
import struct

b = BPF(src_file="tcp_ttfb.c")

b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_set_state")
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_rcv_data")

print(f"{'PID':<8} {'COMM':<16} {'DEST_IP':<16} {'DEST_PORT':<11} {'HANDSHAKE (us)':<15} {'TTFB (us)':<15}")
print("-" * 80)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    packed = struct.pack("=I", event.daddr)
    ip_address = socket.inet_ntoa(packed)

    print((
        f"{event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} "
        f"{ip_address:<16} {event.dport:<11} "
        f"{event.connect_lat_us:<15} {event.ttfb_us:<15}"
    ))

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
