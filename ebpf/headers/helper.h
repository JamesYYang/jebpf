
#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })

#define READ_USER(ptr)                                          \
    ({                                                          \
        typeof(ptr) _val;                                       \
        __builtin_memset((void *)&_val, 0, sizeof(_val));       \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr); \
        _val;                                                   \
    })

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define TCP_EVENT_CONNECT 1
#define TCP_EVENT_ACCEPT 2
#define TCP_EVENT_CLOSE 3

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