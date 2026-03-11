#!/usr/bin/env python3

"""
tcp_backlog_drop - TCP Backlogs drops

"""

from bcc import BPF

b = BPF(src_file="tcp_backlog_drop.c")

print(f"{'LPORT':<10} {'CUR_QLEN':<15} {'MAX_QLEN':<15}")
print("-" * 40)


def print_event(cpu, data, size):
    event = b["events"].event(data)

    print(f"{event.lport:<10} {event.cur_qlen:<15} {event.max_qlen:<15}")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
