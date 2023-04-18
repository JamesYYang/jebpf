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
} tcp_reset_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct net_tcp_event *unused __attribute__((unused));

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header);
}

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
}

SEC("kprobe/tcp_v4_send_reset")
int kp_tcp_v4_send_reset(struct pt_regs *ctx)
{
    struct net_tcp_event *data;
    data = bpf_ringbuf_reserve(&tcp_reset_events, sizeof(*data), 0);
    if (!data)
    {
        return 0;
    }

    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(data->comm, sizeof(data->comm));
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    struct tcphdr *tcp = (struct tcphdr *)skb_transport_header(skb);
    struct iphdr *ip = (struct iphdr *)skb_network_header(skb);
    data->daddr = BPF_CORE_READ(ip, daddr);
    data->saddr = BPF_CORE_READ(ip, saddr);
    data->dport = bpf_ntohs(BPF_CORE_READ(tcp, dest));
    data->sport = bpf_ntohs(BPF_CORE_READ(tcp, source));

    bpf_ringbuf_submit(data, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";