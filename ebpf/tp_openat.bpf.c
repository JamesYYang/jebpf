#include "vmlinux.h"
#include "bpf_helpers.h"
#include "helper.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct sys_openat_event
{
    u32 pid;
    u32 tgid;
    u32 ppid;
    u8 comm[16];
    u8 filename[256];
};

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} sys_enter_openat_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct sys_openat_event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct sys_openat_event *e;

    e = bpf_ringbuf_reserve(&sys_enter_openat_events, sizeof(*e), 0);
    if (!e)
    {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->tgid = READ_KERN(task->tgid);
    e->ppid = READ_KERN(READ_KERN(task->real_parent)->pid);

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)(ctx->args[1]));

    bpf_ringbuf_submit(e, 0);

    return 0;
}