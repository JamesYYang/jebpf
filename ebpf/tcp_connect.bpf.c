#include "vmlinux.h"
#include "helper.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct net_tcp_event
{
    u32 pid;
    u16 event;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 comm[16];
};

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} sys_tcp_connect_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct net_tcp_event *unused __attribute__((unused));

/*
 * inet_sock_set_state tracepoint format.
 *
 * Format: cat /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
 * Code: https://github.com/torvalds/linux/blob/v4.16/include/trace/events/sock.h#L123-L135
 */

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    u16 family = ctx->family;
    u16 event;
    if (family == AF_INET) // ipv4
    {
        if (ctx->oldstate == TCP_SYN_RECV && ctx->newstate == TCP_ESTABLISHED)
        {
            event = TCP_EVENT_ACCEPT;
        }
        else if (ctx->oldstate == TCP_SYN_SENT && ctx->newstate == TCP_ESTABLISHED)
        {
            event = TCP_EVENT_CONNECT;
        }
        else if (ctx->newstate == TCP_CLOSE)
        {
            event = TCP_EVENT_CLOSE;
        }
        else
        {
            return 0;
        }

        struct net_tcp_event *data;
        data = bpf_ringbuf_reserve(&sys_tcp_connect_events, sizeof(*data), 0);
        if (!data)
        {
            return 0;
        }
        data->event = event;
        data->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(data->comm, sizeof(data->comm));
        data->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        data->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        data->sport = ctx->sport;
        data->dport = ctx->dport;

        bpf_ringbuf_submit(data, 0);
    }

    return 0;
}