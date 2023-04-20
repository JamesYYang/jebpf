#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct net_packet_event
{
    u64 ts;
    u32 len;
    u32 ifindex;
    u32 sip;   // 源IP
    u32 dip;   // 目的IP
    u16 sport; // 源端口
    u16 dport; // 目的端口
    u16 ingress;
};

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} tc_capture_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct net_packet_event *unused __attribute__((unused));

static inline bool skb_revalidate_data(struct __sk_buff *skb, u8 **head, u8 **tail, const u32 offset)
{
    if (*head + offset > *tail)
    {
        if (bpf_skb_pull_data(skb, offset) < 0)
        {
            return false;
        }

        *head = (uint8_t *)(long)skb->data;
        *tail = (uint8_t *)(long)skb->data_end;

        if (*head + offset > *tail)
        {
            return false;
        }
    }

    return true;
}

// https://github.com/aquasecurity/tracee/blob/main/pkg/ebpf/c/tracee.bpf.c#L6060
static inline int capture_packets(struct __sk_buff *skb, u16 is_ingress)
{

    // packet data
    unsigned char *data_start = (void *)(long)skb->data;
    unsigned char *data_end = (void *)(long)skb->data_end;
    u32 l4_hdr_off;

    struct net_packet_event *pkt;
    pkt = bpf_ringbuf_reserve(&tc_capture_events, sizeof(*pkt), 0);
    if (!pkt)
    {
        return 0;
    }

    pkt->ts = bpf_ktime_get_ns();
    pkt->len = skb->len;
    pkt->ifindex = skb->ifindex;
    pkt->ingress = is_ingress;

    // Ethernet headers
    struct ethhdr *eth = (struct ethhdr *)data_start;
    // IP headers
    struct iphdr *iph = (struct iphdr *)(data_start + sizeof(struct ethhdr));

    // Simple length check
    if ((data_start + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
    {
        return TC_ACT_OK;
    }

    // filter out non-IP packets
    // TODO support IPv6
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }
    l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off))
    {
        return TC_ACT_OK;
    }

    // filter out non-TCP packets
    if (iph->protocol != IPPROTO_TCP)
    {
        return TC_ACT_OK;
    }

    pkt->dip = iph->daddr;
    pkt->sip = iph->saddr;

    if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off + sizeof(struct tcphdr)))
    {
        return TC_ACT_OK;
    }
    struct tcphdr *tcp = (struct tcphdr *)(data_start + l4_hdr_off);

    if (tcp->source == bpf_htons(22) || tcp->dest == bpf_htons(22))
    {
        return TC_ACT_OK;
    }

    pkt->dport = bpf_ntohs(tcp->dest);
    pkt->sport = bpf_ntohs(tcp->source);

    bpf_ringbuf_submit(pkt, 0);

    return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb)
{
    return capture_packets(skb, 0);
};

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb)
{
    return capture_packets(skb, 1);
};

char _license[] SEC("license") = "GPL";