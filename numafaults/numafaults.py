#!/usr/bin/env python3

"""
numafaults - NUMA Memory Locality Analysis Tool using eBPF

Description:
    This tool traces the `task_numa_fault` kernel function to measure
    memory locality for processes on NUMA (Non-Uniform Memory Access) systems.

     - LOCAL FAULTS: Memory pages accessed on the same NUMA node as the CPU.
     - REMOTE FAULTS: Memory pages accessed on a different NUMA node (slower).

Output:
    Updates every second, showing the number of local and remote faults
    per PID, and calculating the overall Locality % (higher is better).
"""

import time
from bcc import BPF

b = BPF(src_file="numafaults.c")

print(f"{'PID':<10} {'COMM':<10} {'LOCAL FAULTS':<15} {'REMOTE FAULTS':<15} {'LOCALITY %':<15}")
try:
    while True:
        time.sleep(1)
        numa_faults = b["numa_faults"]
        for pid, values in numa_faults.items():
            comm = values[0].comm.decode('utf-8', 'replace')
            local_faults = sum(v.local_faults for v in values)
            remote_faults = sum(v.remote_faults for v in values)
            total_faults = local_faults + remote_faults
            locality = (local_faults / total_faults) * 100 if total_faults > 0 else 0

            print(f"{pid.value:<10} {comm:<10} {local_faults:<15} {remote_faults:<15} {locality:<15.2f}")

        numa_faults.clear()
        print("-" * 65)
except KeyboardInterrupt:
    print("\nTschüss!")
