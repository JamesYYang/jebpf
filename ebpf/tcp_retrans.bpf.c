#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} tcp_retrans_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct net_tcp_event *unused __attribute__((unused));

SEC("kprobe/tcp_retransmit_skb")
int kp_tcp_retransmit_skb(struct pt_regs *ctx)
{

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sock_common sk_common = BPF_CORE_READ(sk, __sk_common);
    u16 family = sk_common.skc_family;

    if (family == AF_INET)
    {
        struct net_tcp_event *data;
        data = bpf_ringbuf_reserve(&tcp_retrans_events, sizeof(*data), 0);
        if (!data)
        {
            return 0;
        }
        data->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(data->comm, sizeof(data->comm));

        data->daddr = sk_common.skc_daddr;
        data->saddr = sk_common.skc_rcv_saddr;
        data->dport = bpf_ntohs(sk_common.skc_dport);
        data->sport = sk_common.skc_num;

        bpf_ringbuf_submit(data, 0);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";