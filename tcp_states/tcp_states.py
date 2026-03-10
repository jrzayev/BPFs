#!/usr/bin/env python3

"""
tcp_states - TCP State Tracker

You can find what means each state in here:
https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h
"""

from bcc import BPF

b = BPF(src_file="tcp_states.c")

b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

print(f"{'PID':<8} {'COMM':<16} {'LPORT':<10} {'DPORT':<10} {'OLD_STATE':<10} {'NEW_STATE':<10}")
print("-" * 70)


def print_event(cpu, data, size):
    event = b["events"].event(data)

    print((
        f"{event.pid:<8} {event.comm.decode('utf-8', 'replace'):<16} "
        f"{event.lport:<10} {event.dport:<10} {event.old_state:<10} {event.new_state:<10}"
    ))

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
