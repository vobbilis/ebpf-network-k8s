#ifndef __MAPS_H
#define __MAPS_H

#include "common.h"

// Connection tracking map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} conns SEC(".maps");

// Filter rules map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, struct FilterRule);
} filter_map SEC(".maps");

// Global metrics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_metrics);
} metrics SEC(".maps");

// TCP state metrics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, TCP_STATE_MAX);
    __type(key, __u32);
    __type(value, __u32);
} tcp_state_stats SEC(".maps");

// Filter rule metrics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, struct rule_metrics);
} rule_stats SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// Pod ID to metadata map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u32);
} pod_map SEC(".maps");

// LRU cache for connection tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} conn_cache SEC(".maps");

#endif /* __MAPS_H */ 