#!/usr/bin/env python3

"""
tcp_latency - TCP/IP Stack Latency Profiler using eBPF

Description:
    Measures the latency of the Linux TCP/IP stack for RX and TX paths.

    - RX Latency: Time from a packet entering the socket queue to being read
      by the application. Reports receive buffer usage to detect application-side bottlenecks.
    - TX Latency: Time from packet creation to reaching the device queue.

Output:
    Real-time events for packets with a stack latency exceeding 1 millisecond.
"""

from bcc import BPF
import time

b = BPF(src_file="tcp_latency.c")

b.attach_kprobe(event="tcp_data_queue", fn_name="trace_start_queue")
b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_end_recv")
b.attach_kprobe(event="__tcp_transmit_skb", fn_name="trace_tx_start")
b.attach_kprobe(event="__dev_queue_xmit", fn_name="trace_tx_end")

print(f"{'RX/TX':<8} {'PID':<8} {'COMM':<16} {'DELAY (us)':<12} {'BUFFER FULL %':<15}")
print("-" * 65)

def print_event(cpu, data, size):
    event = b["events"].event(data)

    if event.is_tx == 0:
        print(f"{'RX':<8} {event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} {event.delay_us:<12} {event.usage_percent:<15}")
    else:
        print(f"{'TX':<8} {event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} {event.delay_us:<12} {'N/A':<15}")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
