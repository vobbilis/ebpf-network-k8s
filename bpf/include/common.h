#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 100000
#define TCP_STATE_MAX 16

// Connection key structure
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 pod_id;
};

// Connection info structure
struct conn_info {
    __u64 rx_bytes;
    __u64 tx_bytes;
    __u64 rx_packets;
    __u64 tx_packets;
    __u64 retransmit_bytes;
    __u64 last_retrans_ts;
    __u8  tcp_state;
    __u8  ct_state;
    __u32 ct_mark;
    __u64 start_ts;
    __u64 last_seen;
    __u32 rx_dropped;
};

// Filter rule structure
struct FilterRule {
    __u32 SrcIP[4];    // Source IP (support for IPv6)
    __u32 DstIP[4];    // Destination IP (support for IPv6)
    __u32 SrcMask[4];  // Source netmask
    __u32 DstMask[4];  // Destination netmask
    __u16 PortMin;     // Port range start
    __u16 PortMax;     // Port range end
    __u8  Protocol;    // Protocol (TCP=6, UDP=17, 0=both)
    __u8  Action;      // Action (0=deny, 1=allow)
};

// Global metrics structure
struct global_metrics {
    __u64 total_connections_seen;
    __u64 total_connections_tracked;
    __u64 dropped_connections;
    __u64 filtered_connections;
    __u64 active_tcp_connections;
    __u64 active_udp_flows;
    __u64 total_tcp_retransmits;
    __u64 total_tcp_retransmit_bytes;
    __u64 total_udp_errors;
};

// Per-rule metrics structure
struct rule_metrics {
    __u64 total_checked;
    __u64 total_matched;
    __u64 total_allowed;
    __u64 total_denied;
    __u64 bytes_matched;
};

// Event structure for userspace communication
struct conn_event {
    __u64 timestamp;
    __u32 event_type;
    struct conn_key key;
    struct conn_info info;
};

// Helper function to get current timestamp
static __always_inline __u64 get_timestamp(void) {
    return bpf_ktime_get_ns();
}

// Helper function to update connection metrics
static __always_inline void update_metrics(struct conn_info *info, __u32 bytes, bool is_rx) {
    if (is_rx) {
        info->rx_bytes += bytes;
        info->rx_packets++;
    } else {
        info->tx_bytes += bytes;
        info->tx_packets++;
    }
    info->last_seen = get_timestamp();
}

// Helper function to update global metrics
static __always_inline void update_global_metrics(__u32 metric_type, __u64 value) {
    __u32 key = 0;
    struct global_metrics *metrics;
    
    metrics = bpf_map_lookup_elem(&metrics, &key);
    if (!metrics)
        return;
        
    switch (metric_type) {
        case 0: // Total connections seen
            __sync_fetch_and_add(&metrics->total_connections_seen, value);
            break;
        case 1: // Total connections tracked
            __sync_fetch_and_add(&metrics->total_connections_tracked, value);
            break;
        case 2: // Dropped connections
            __sync_fetch_and_add(&metrics->dropped_connections, value);
            break;
        case 3: // Filtered connections
            __sync_fetch_and_add(&metrics->filtered_connections, value);
            break;
        case 4: // Active TCP connections
            __sync_fetch_and_add(&metrics->active_tcp_connections, value);
            break;
        case 5: // Active UDP flows
            __sync_fetch_and_add(&metrics->active_udp_flows, value);
            break;
    }
}

// Helper function to update rule metrics
static __always_inline void update_rule_metrics(__u32 rule_index, bool matched, bool allowed, __u32 bytes) {
    struct rule_metrics *metrics;
    
    metrics = bpf_map_lookup_elem(&rule_stats, &rule_index);
    if (!metrics)
        return;
        
    __sync_fetch_and_add(&metrics->total_checked, 1);
    if (matched) {
        __sync_fetch_and_add(&metrics->total_matched, 1);
        __sync_fetch_and_add(&metrics->bytes_matched, bytes);
        if (allowed)
            __sync_fetch_and_add(&metrics->total_allowed, 1);
        else
            __sync_fetch_and_add(&metrics->total_denied, 1);
    }
}

// Helper function to update TCP state statistics
static __always_inline void update_tcp_state_stats(__u8 old_state, __u8 new_state) {
    __u32 key;
    __u32 *count;
    
    if (old_state < TCP_STATE_MAX) {
        key = old_state;
        count = bpf_map_lookup_elem(&tcp_state_stats, &key);
        if (count)
            __sync_fetch_and_sub(count, 1);
    }
    
    if (new_state < TCP_STATE_MAX) {
        key = new_state;
        count = bpf_map_lookup_elem(&tcp_state_stats, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
    }
}

#endif /* __COMMON_H */ 