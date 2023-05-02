#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"

struct sys_capable_event
{
    u32 pid;
    u32 uid;
    u8 comm[16];
    u8 cap;
    u8 audit;
};

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} sys_capable_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct sys_capable_event *unused __attribute__((unused));

SEC("kprobe/cap_capable")
int kp_sys_capable(struct pt_regs *ctx)
{
    struct sys_capable_event *e;
    e = bpf_ringbuf_reserve(&sys_capable_events, sizeof(*e), 0);
    if (!e)
    {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->cap = PT_REGS_PARM3(ctx);
    e->audit = PT_REGS_PARM4(ctx);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // if (e->audit & CAP_OPT_NOAUDIT)
    //     return 0;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";