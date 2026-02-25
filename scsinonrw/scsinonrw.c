#include <uapi/linux/ptrace.h>

struct req_key_t {
    u32 host;
    u32 channel;
    u32 id;
    u32 lun;
    u32 opcode;
};

struct nonrw_s {
    u64 ts;
    u64 opcode;
    u32 host;
    u32 channel;
    u32 id;
    u32 lun;
    u32 result;
};

BPF_HASH(nonrw, struct req_key_t, u64, 10240);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(scsi, scsi_dispatch_cmd_start) {
    u64 opcode = args->opcode;

    if (opcode == 0x08 || opcode == 0x28 || opcode == 0x88)
        return 0;
    if (opcode == 0x0A || opcode == 0x2A || opcode == 0x8A)
        return 0;

    struct req_key_t key = {};
    key.host = args->host_no;
    key.channel = args->channel;
    key.id = args->id;
    key.lun = args->lun;
    key.opcode = opcode;

    u64 ts = bpf_ktime_get_ns();
    nonrw.update(&key, &ts);

    return 0;
}

TRACEPOINT_PROBE(scsi, scsi_dispatch_cmd_done) {
    struct req_key_t key = {};
    key.host = args->host_no;
    key.channel = args->channel;
    key.id = args->id;
    key.lun = args->lun;
    key.opcode = args->opcode;

    u64 *start_ts = nonrw.lookup(&key);
    if (start_ts == 0)
        return 0;

    struct nonrw_s cmd_info = {};
    cmd_info.ts = bpf_ktime_get_ns() - *start_ts;
    cmd_info.opcode = args->opcode;
    cmd_info.host = args->host_no;
    cmd_info.channel = args->channel;
    cmd_info.id = args->id;
    cmd_info.lun = args->lun;
    cmd_info.result = args->result;

    events.perf_submit(args, &cmd_info, sizeof(cmd_info));
    nonrw.delete(&key);

    return 0;
}
