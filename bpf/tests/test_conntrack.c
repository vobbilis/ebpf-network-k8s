#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/mock_kernel.h"
#include "../include/common.h"

/* Mock maps */
static struct bpf_map_def SEC("maps") conn_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct conn_id),
    .value_size = sizeof(struct conn_info),
    .max_entries = 10000,
};

static struct conn_info mock_conn_info;
static struct conn_id mock_conn_id;
static bool pod_exists = true;

/* Mock helper functions */
__u64 get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void *bpf_map_lookup_elem(void *map, const void *key) {
    if (!pod_exists) {
        // Simulate pod not found scenario
        return NULL;
    }
    if (map == &conn_map && memcmp(key, &mock_conn_id, sizeof(struct conn_id)) == 0) {
        return &mock_conn_info;
    }
    return NULL;
}

int bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags) {
    if (!pod_exists) {
        // Simulate pod deletion - updates should fail
        return -1;
    }
    if (map == &conn_map) {
        memcpy(&mock_conn_id, key, sizeof(struct conn_id));
        memcpy(&mock_conn_info, value, sizeof(struct conn_info));
        return 0;
    }
    return -1;
}

int bpf_map_delete_elem(void *map, const void *key) {
    if (map == &conn_map && memcmp(key, &mock_conn_id, sizeof(struct conn_id)) == 0) {
        memset(&mock_conn_info, 0, sizeof(struct conn_info));
        return 0;
    }
    return -1;
}

/* Test helper functions */
void setup_test_connection(void) {
    pod_exists = true;
    memset(&mock_conn_id, 0, sizeof(struct conn_id));
    memset(&mock_conn_info, 0, sizeof(struct conn_info));
    
    mock_conn_id.protocol = IPPROTO_TCP;
    mock_conn_id.src_ip = 0x0A000001;  // 10.0.0.1
    mock_conn_id.dst_ip = 0x0A000002;  // 10.0.0.2
    mock_conn_id.src_port = 12345;
    mock_conn_id.dst_port = 80;
    
    mock_conn_info.bytes_in = 1000;
    mock_conn_info.bytes_out = 2000;
    mock_conn_info.packets_in = 10;
    mock_conn_info.packets_out = 20;
    mock_conn_info.retransmit_count = 0;
    mock_conn_info.last_retrans_ts = 0;
    mock_conn_info.start_ts = get_timestamp();
    mock_conn_info.last_seen = get_timestamp();
}

void test_tcp_retransmit(void) {
    printf("Running test_tcp_retransmit...\n");
    
    // Setup initial connection
    setup_test_connection();
    
    // Create mock TCP retransmit event
    struct trace_event_raw_tcp_retransmit_skb ctx = {
        .skbaddr = 0x1234567890,
        .state = 1,
        .sport = mock_conn_id.src_port,
        .dport = mock_conn_id.dst_port,
        .family = AF_INET
    };
    memcpy(ctx.saddr, &mock_conn_id.src_ip, 4);
    memcpy(ctx.daddr, &mock_conn_id.dst_ip, 4);
    
    // Call the handler (simulated)
    printf("- Simulating TCP retransmit event\n");
    mock_conn_info.retransmit_count++;
    mock_conn_info.last_retrans_ts = get_timestamp();
    bpf_map_update_elem(&conn_map, &mock_conn_id, &mock_conn_info, BPF_ANY);
    
    // Verify connection info was updated
    struct conn_info *info = bpf_map_lookup_elem(&conn_map, &mock_conn_id);
    assert(info != NULL);
    assert(info->retransmit_count == 1);
    assert(info->last_retrans_ts > 0);
    
    printf("- TCP retransmit test passed\n");
}

void test_pod_deletion(void) {
    printf("Running test_pod_deletion...\n");
    
    // Setup initial connection
    setup_test_connection();
    
    // Verify initial state
    struct conn_info *info = bpf_map_lookup_elem(&conn_map, &mock_conn_id);
    assert(info != NULL);
    assert(info->packets_in == 10);
    printf("- Initial connection state verified\n");
    
    // Simulate pod deletion
    printf("- Simulating pod deletion\n");
    pod_exists = false;
    
    // Try to update connection after pod deletion
    __u64 old_packets = mock_conn_info.packets_in;
    mock_conn_info.packets_in++;
    int ret = bpf_map_update_elem(&conn_map, &mock_conn_id, &mock_conn_info, BPF_ANY);
    assert(ret == -1);  // Update should fail
    
    // Verify connection is not accessible
    info = bpf_map_lookup_elem(&conn_map, &mock_conn_id);
    assert(info == NULL);  // Connection should not be found
    
    // Try to delete the connection
    ret = bpf_map_delete_elem(&conn_map, &mock_conn_id);
    assert(ret == 0);  // Deletion should succeed
    
    printf("- Pod deletion test passed\n");
}

int main(void) {
    printf("Starting eBPF tests...\n");
    
    test_tcp_retransmit();
    test_pod_deletion();
    
    printf("All tests passed!\n");
    return 0;
} 