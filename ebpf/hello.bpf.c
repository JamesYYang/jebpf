#include "vmlinux.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_printk("BPF triggered from PID %d and COMM %s.\n", pid, comm);

    return 0;
}