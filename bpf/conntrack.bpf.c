#include "include/common.h"
#include "include/maps.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

char LICENSE[] SEC("license") = "GPL";

// Helper: Create connection key from network headers
static __always_inline void create_conn_key(struct conn_key *key,
                                          __u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port,
                                          __u8 proto, __u32 pod_id) {
    key->src_ip = src_ip;
    key->dst_ip = dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->protocol = proto;
    key->pod_id = pod_id;
}

// Helper: Check if connection matches filter rule
static __always_inline bool check_filter_match(struct conn_key *key, struct FilterRule *rule) {
    if (rule->Protocol != 0 && rule->Protocol != key->protocol)
        return false;
        
    if (rule->SrcMask[0] != 0) {
        if ((key->src_ip & rule->SrcMask[0]) != (rule->SrcIP[0] & rule->SrcMask[0]))
            return false;
    }
    
    if (rule->DstMask[0] != 0) {
        if ((key->dst_ip & rule->DstMask[0]) != (rule->DstIP[0] & rule->DstMask[0]))
            return false;
    }
    
    if (rule->PortMin != 0 || rule->PortMax != 0) {
        if (key->src_port < rule->PortMin || key->src_port > rule->PortMax)
            if (key->dst_port < rule->PortMin || key->dst_port > rule->PortMax)
                return false;
    }
    
    return true;
}

// Helper: Check connection against filter rules
static __always_inline __u8 check_conn_filters(struct conn_key *key) {
    struct FilterRule *rule;
    __u32 index = 0;
    
    // Check each filter rule
    while (1) {
        rule = bpf_map_lookup_elem(&filter_map, &index);
        if (!rule)
            break;
            
        if (check_filter_match(key, rule))
            return rule->Action;
            
        index++;
        if (index > 1000) // Safety limit
            break;
    }
    
    // Default deny if no rules match
    return 0;
}

// Helper: Send event to userspace
static __always_inline int send_event(struct conn_key *key, struct conn_info *info, __u32 event_type) {
    struct conn_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return -1;
        
    event->key = *key;
    event->info = *info;
    event->timestamp = get_timestamp();
    event->event_type = event_type;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// TCP State tracking
SEC("tracepoint/tcp/tcp_set_state")
int trace_tcp_state(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    struct conn_key key = {};
    struct conn_info *info, new_info = {};
    __u16 sport = 0, dport = 0;
    __u32 saddr = 0, daddr = 0;
    __u8 state = ctx->state;
    
    // Extract connection details from context
    bpf_probe_read(&sport, sizeof(sport), &ctx->sport);
    bpf_probe_read(&dport, sizeof(dport), &ctx->dport);
    bpf_probe_read(&saddr, sizeof(saddr), &ctx->saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &ctx->daddr);
    
    create_conn_key(&key, saddr, daddr, sport, dport, IPPROTO_TCP, 0);
    
    // Update total connections seen
    update_global_metrics(0, 1);
    
    info = bpf_map_lookup_elem(&conns, &key);
    if (!info) {
        new_info.tcp_state = state;
        new_info.start_ts = get_timestamp();
        new_info.last_seen = new_info.start_ts;
        
        if (bpf_map_update_elem(&conns, &key, &new_info, BPF_ANY) == 0) {
            update_global_metrics(1, 1); // Tracked connections
            update_global_metrics(4, 1); // Active TCP connections
            update_tcp_state_stats(0, state);
            send_event(&key, &new_info, 1); // New connection
        } else {
            update_global_metrics(2, 1); // Dropped connections
        }
    } else {
        update_tcp_state_stats(info->tcp_state, state);
        info->tcp_state = state;
        info->last_seen = get_timestamp();
        send_event(&key, info, 2); // State update
    }
    
    return 0;
}

// UDP tracking
SEC("tracepoint/udp/udp_fail")
int trace_udp_error(struct trace_event_raw_udp_event_sk_skb *ctx) {
    struct conn_key key = {};
    struct conn_info *info, new_info = {};
    __u16 sport = 0, dport = 0;
    __u32 saddr = 0, daddr = 0;
    
    // Extract connection details
    bpf_probe_read(&sport, sizeof(sport), &ctx->sport);
    bpf_probe_read(&dport, sizeof(dport), &ctx->dport);
    bpf_probe_read(&saddr, sizeof(saddr), &ctx->saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &ctx->daddr);
    
    create_conn_key(&key, saddr, daddr, sport, dport, IPPROTO_UDP, 0);
    
    // Update total connections seen
    update_global_metrics(0, 1);
    
    info = bpf_map_lookup_elem(&conns, &key);
    if (!info) {
        new_info.start_ts = get_timestamp();
        new_info.last_seen = new_info.start_ts;
        new_info.rx_dropped = 1;
        
        if (bpf_map_update_elem(&conns, &key, &new_info, BPF_ANY) == 0) {
            update_global_metrics(1, 1); // Tracked connections
            update_global_metrics(5, 1); // Active UDP flows
            send_event(&key, &new_info, 3); // New UDP error
        } else {
            update_global_metrics(2, 1); // Dropped connections
        }
    } else {
        info->rx_dropped++;
        info->last_seen = get_timestamp();
        send_event(&key, info, 4); // UDP error update
    }
    
    return 0;
}

// Conntrack event handling
SEC("tracepoint/nf_conntrack/nf_conntrack_update")
int trace_conntrack(struct trace_event_raw_nf_conntrack *ctx) {
    struct conn_key key = {};
    struct conn_info *info, new_info = {};
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    __u8 proto = 0;
    
    // Extract connection details
    bpf_probe_read(&saddr, sizeof(saddr), &ctx->orig.src_ip);
    bpf_probe_read(&daddr, sizeof(daddr), &ctx->orig.dst_ip);
    bpf_probe_read(&sport, sizeof(sport), &ctx->orig.src_port);
    bpf_probe_read(&dport, sizeof(dport), &ctx->orig.dst_port);
    bpf_probe_read(&proto, sizeof(proto), &ctx->orig.proto);
    
    create_conn_key(&key, saddr, daddr, sport, dport, proto, 0);
    
    // Update total connections seen
    update_global_metrics(0, 1);
    
    // Check filter rules
    __u8 action = check_conn_filters(&key);
    update_global_metrics(3, 1); // Filtered connections
    
    // Update connection info based on filter action
    info = bpf_map_lookup_elem(&conns, &key);
    if (!info) {
        if (action == 0) { // Deny
            return 0;
        }
        
        // Initialize new connection
        new_info.start_ts = get_timestamp();
        new_info.last_seen = new_info.start_ts;
        new_info.ct_state = ctx->state;
        new_info.ct_mark = ctx->mark;
        
        if (bpf_map_update_elem(&conns, &key, &new_info, BPF_ANY) == 0) {
            update_global_metrics(1, 1); // Tracked connections
            if (proto == IPPROTO_TCP)
                update_global_metrics(4, 1); // Active TCP connections
            else if (proto == IPPROTO_UDP)
                update_global_metrics(5, 1); // Active UDP flows
            send_event(&key, &new_info, 1); // New connection
        } else {
            update_global_metrics(2, 1); // Dropped connections
        }
    } else {
        if (action == 0) { // Deny
            if (proto == IPPROTO_TCP)
                update_global_metrics(4, -1); // Decrease active TCP connections
            else if (proto == IPPROTO_UDP)
                update_global_metrics(5, -1); // Decrease active UDP flows
            
            bpf_map_delete_elem(&conns, &key);
            send_event(&key, info, 2); // Connection terminated
            return 0;
        }
        
        // Update existing connection
        info->ct_state = ctx->state;
        info->ct_mark = ctx->mark;
        info->last_seen = get_timestamp();
        send_event(&key, info, 5); // Conntrack update
    }
    
    return 0;
}

// cgroup/skb ingress handler
SEC("cgroup_skb/ingress")
int trace_ingress_skb(struct __sk_buff *skb) {
    struct conn_key key = {};
    struct conn_info *info, new_info = {};
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return 1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 1;
        
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return 1;
        
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return 1;
        
    __u32 pod_id = 0;
    pod_id = bpf_get_cgroup_classid(skb);
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)(ip + 1);
        if ((void*)(tcp + 1) > data_end)
            return 1;
            
        create_conn_key(&key,
                       ip->saddr, ip->daddr,
                       bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest),
                       IPPROTO_TCP, pod_id);
                       
        info = bpf_map_lookup_elem(&conns, &key);
        if (!info) {
            new_info.start_ts = get_timestamp();
            new_info.last_seen = new_info.start_ts;
            bpf_map_update_elem(&conns, &key, &new_info, BPF_ANY);
            info = &new_info;
        }
        
        update_metrics(info, skb->len, true);
        send_event(&key, info, 6); // TCP ingress
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)(ip + 1);
        if ((void*)(udp + 1) > data_end)
            return 1;
            
        create_conn_key(&key,
                       ip->saddr, ip->daddr,
                       bpf_ntohs(udp->source), bpf_ntohs(udp->dest),
                       IPPROTO_UDP, pod_id);
                       
        info = bpf_map_lookup_elem(&conns, &key);
        if (!info) {
            new_info.start_ts = get_timestamp();
            new_info.last_seen = new_info.start_ts;
            bpf_map_update_elem(&conns, &key, &new_info, BPF_ANY);
            info = &new_info;
        }
        
        update_metrics(info, skb->len, true);
        send_event(&key, info, 7); // UDP ingress
    }
    
    return 1;
}

// cgroup/skb egress handler
SEC("cgroup_skb/egress")
int trace_egress_skb(struct __sk_buff *skb) {
    struct conn_key key = {};
    struct conn_info *info, new_info = {};
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return 1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 1;
        
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return 1;
        
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return 1;
        
    __u32 pod_id = 0;
    pod_id = bpf_get_cgroup_classid(skb);
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)(ip + 1);
        if ((void*)(tcp + 1) > data_end)
            return 1;
            
        create_conn_key(&key,
                       ip->saddr, ip->daddr,
                       bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest),
                       IPPROTO_TCP, pod_id);
                       
        info = bpf_map_lookup_elem(&conns, &key);
        if (!info) {
            new_info.start_ts = get_timestamp();
            new_info.last_seen = new_info.start_ts;
            bpf_map_update_elem(&conns, &key, &new_info, BPF_ANY);
            info = &new_info;
        }
        
        update_metrics(info, skb->len, false);
        send_event(&key, info, 8); // TCP egress
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)(ip + 1);
        if ((void*)(udp + 1) > data_end)
            return 1;
            
        create_conn_key(&key,
                       ip->saddr, ip->daddr,
                       bpf_ntohs(udp->source), bpf_ntohs(udp->dest),
                       IPPROTO_UDP, pod_id);
                       
        info = bpf_map_lookup_elem(&conns, &key);
        if (!info) {
            new_info.start_ts = get_timestamp();
            new_info.last_seen = new_info.start_ts;
            bpf_map_update_elem(&conns, &key, &new_info, BPF_ANY);
            info = &new_info;
        }
        
        update_metrics(info, skb->len, false);
        send_event(&key, info, 9); // UDP egress
    }
    
    return 1;
}

// TCP Retransmission tracking
SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    struct conn_key key = {};
    struct conn_info *info;
    __u16 sport = 0, dport = 0;
    __u32 saddr = 0, daddr = 0;
    __u32 len = 0;
    
    // Extract connection details
    bpf_probe_read(&sport, sizeof(sport), &ctx->sport);
    bpf_probe_read(&dport, sizeof(dport), &ctx->dport);
    bpf_probe_read(&saddr, sizeof(saddr), &ctx->saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &ctx->daddr);
    bpf_probe_read(&len, sizeof(len), &ctx->len);
    
    create_conn_key(&key, saddr, daddr, sport, dport, IPPROTO_TCP, 0);
    
    info = bpf_map_lookup_elem(&conns, &key);
    if (info) {
        info->retransmits++;
        info->retransmit_bytes += len;
        info->last_retrans_ts = bpf_ktime_get_ns();
        info->last_seen = info->last_retrans_ts;
        send_event(&key, info, 7); // EVENT_TYPE_TCP_RETRANSMIT
    }
    
    return 0;
} 