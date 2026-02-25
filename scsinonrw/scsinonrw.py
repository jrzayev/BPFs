#!/usr/bin/env python3

"""
scsisnoop - SCSI Non-Read/Write Command Tracing Tool using eBPF

Description:
    This tool traces the lower-level SCSI subsystem (`scsi_dispatch_cmd_start`
    and `scsi_dispatch_cmd_done` tracepoints) to capture and measure the hardware
    latency of disk control commands, explicitly ignoring standard READ and WRITE operations:

     - Captures: SYNCHRONIZE_CACHE (flushes), UNMAP (TRIM), INQUIRY,
       START_STOP_UNIT (disk spin up/down), and other metadata/control commands.
     - Ignores: Standard bulk data transfers (OpCodes 0x08, 0x28, 0x88, 0x0A, 0x2A, 0x8A).

Output:
    Prints a real-time event log for every matched SCSI command, showing the
    timestamp, mapped block device (e.g., sda), hex opcode, translated command name,
    hardware execution latency (ms), and the final completion status (OK/FAILED).
"""

import time
import os
from bcc import BPF

SCSI_OPCODES = {
    0x00: "TEST_UNIT_READY",
    0x03: "REQUEST_SENSE",
    0x12: "INQUIRY",
    0x1B: "START_STOP_UNIT",
    0x2F: "VERIFY",
    0x35: "SYNCHRONIZE_CACHE",
    0x42: "UNMAP (TRIM)",
    0x5E: "PERSISTENT_RESERVE"
}

def get_disk_name(host, channel, id, lun):
    path = f"/sys/class/scsi_device/{host}:{channel}:{id}:{lun}/device/block/"
    try:
        if os.path.exists(path):
            dirs = os.listdir(path)
            if dirs:
                return dirs[0]
    except Exception:
        pass
    return f"host{host}"

b = BPF(src_file="scsinonrw.c")

print(f"{'TIME':<10} {'DEVICE':<8} {'OPCODE':<8} {'COMMAND_NAME':<20} {'LATENCY (ms)':<15} {'RESULT':<8}")
print("-" * 75)

def print_event(cpu, data, size):
    event = b["events"].event(data)

    time_str = time.strftime("%H:%M:%S")
    device = get_disk_name(event.host, event.channel, event.id, event.lun)
    opcode_hex = f"0x{event.opcode:02X}"
    cmd_name = SCSI_OPCODES.get(event.opcode, "UNKNOWN")
    latency_ms = event.ts / 1000000.0
    result_str = "OK" if event.result == 0 else "FAILED"

    print(f"{time_str:<10} {device:<8} {opcode_hex:<8} {cmd_name:<20} {latency_ms:<15.2f} {result_str:<8}")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nTschüss!")
