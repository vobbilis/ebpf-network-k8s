#ifndef __MOCK_KERNEL_H
#define __MOCK_KERNEL_H

#include <stdint.h>
#include <stdbool.h>

/* Mock kernel types */
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;
typedef __u64 __be64;
typedef __u32 __be32;
typedef __u16 __be16;

/* Mock BPF definitions */
#define SEC(NAME)
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

/* Mock network types */
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* Mock tracepoint context */
struct trace_event_raw_tcp_retransmit_skb {
    __u64 skbaddr;
    __u32 state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

/* Mock BPF context */
struct bpf_context {
    __u64 args[5];
};

/* Function declarations - implementations provided by test */
void *bpf_map_lookup_elem(void *map, const void *key);
int bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
__u64 get_timestamp(void);

#endif /* __MOCK_KERNEL_H */ 