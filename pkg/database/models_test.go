package database

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) *Store {
	ctx := context.Background()
	connString := "postgres://postgres:postgres@localhost:5432/conntrack_test?sslmode=disable"

	// Create test database
	pool, err := pgxpool.Connect(ctx, "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	require.NoError(t, err)

	_, err = pool.Exec(ctx, "DROP DATABASE IF EXISTS conntrack_test")
	require.NoError(t, err)

	_, err = pool.Exec(ctx, "CREATE DATABASE conntrack_test")
	require.NoError(t, err)

	pool.Close()

	// Connect to test database
	store, err := NewStore(ctx, connString)
	require.NoError(t, err)

	// Run migrations
	// Note: In a real implementation, you'd use a migration tool
	_, err = store.db.Exec(ctx, `
        CREATE EXTENSION IF NOT EXISTS timescaledb;
        
        CREATE TABLE connections (
            id BIGSERIAL PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            pod_name VARCHAR(255),
            namespace VARCHAR(255),
            container_id VARCHAR(64),
            protocol INTEGER NOT NULL,
            src_ip INET NOT NULL,
            src_port INTEGER NOT NULL,
            dst_ip INET NOT NULL,
            dst_port INTEGER NOT NULL,
            tcp_state SMALLINT,
            retransmits INTEGER,
            rtt_usec INTEGER,
            window_size INTEGER,
            udp_rx_dropped INTEGER,
            udp_tx_dropped INTEGER,
            ct_state INTEGER,
            ct_zone INTEGER,
            ct_mark INTEGER,
            ct_labels BYTEA,
            nat_ip INET,
            nat_port INTEGER,
            bytes_in BIGINT NOT NULL DEFAULT 0,
            bytes_out BIGINT NOT NULL DEFAULT 0,
            packets_in BIGINT NOT NULL DEFAULT 0,
            packets_out BIGINT NOT NULL DEFAULT 0,
            start_ts TIMESTAMPTZ NOT NULL,
            last_seen TIMESTAMPTZ NOT NULL
        );
        
        SELECT create_hypertable('connections', 'timestamp');
    `)
	require.NoError(t, err)

	return store
}

func TestInsertConnection(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	ctx := context.Background()

	tcpState := 1
	conn := &Connection{
		Timestamp:   time.Now(),
		PodName:     "test-pod",
		Namespace:   "test-ns",
		ContainerID: "test-container",
		Protocol:    6,
		SrcIP:       net.ParseIP("10.0.0.1"),
		SrcPort:     12345,
		DstIP:       net.ParseIP("10.0.0.2"),
		DstPort:     80,
		TCPState:    &tcpState,
		BytesIn:     1000,
		BytesOut:    2000,
		PacketsIn:   10,
		PacketsOut:  20,
		StartTS:     time.Now(),
		LastSeen:    time.Now(),
	}

	err := store.InsertConnection(ctx, conn)
	assert.NoError(t, err)

	// Verify insertion
	var count int
	err = store.db.QueryRow(ctx, "SELECT COUNT(*) FROM connections").Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestUpdateConnection(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	ctx := context.Background()

	// Insert initial connection
	tcpState := 1
	conn := &Connection{
		Timestamp:   time.Now(),
		PodName:     "test-pod",
		Namespace:   "test-ns",
		ContainerID: "test-container",
		Protocol:    6,
		SrcIP:       net.ParseIP("10.0.0.1"),
		SrcPort:     12345,
		DstIP:       net.ParseIP("10.0.0.2"),
		DstPort:     80,
		TCPState:    &tcpState,
		BytesIn:     1000,
		BytesOut:    2000,
		PacketsIn:   10,
		PacketsOut:  20,
		StartTS:     time.Now(),
		LastSeen:    time.Now(),
	}

	err := store.InsertConnection(ctx, conn)
	require.NoError(t, err)

	// Update connection
	tcpState = 2
	conn.TCPState = &tcpState
	conn.BytesIn = 2000
	conn.LastSeen = time.Now()

	err = store.UpdateConnection(ctx, conn)
	assert.NoError(t, err)

	// Verify update
	var bytesIn int64
	var updatedState int
	err = store.db.QueryRow(ctx, `
        SELECT bytes_in, tcp_state
        FROM connections
        WHERE src_ip = $1 AND dst_ip = $2 AND src_port = $3 AND dst_port = $4 AND protocol = $5
    `, conn.SrcIP, conn.DstIP, conn.SrcPort, conn.DstPort, conn.Protocol).Scan(&bytesIn, &updatedState)

	assert.NoError(t, err)
	assert.Equal(t, int64(2000), bytesIn)
	assert.Equal(t, 2, updatedState)
}

func TestGetConnectionStats(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	ctx := context.Background()

	// Insert test data
	now := time.Now()
	tcpState := 1

	// TCP connection
	conn1 := &Connection{
		Timestamp:  now,
		PodName:    "test-pod",
		Namespace:  "test-ns",
		Protocol:   6,
		SrcIP:      net.ParseIP("10.0.0.1"),
		SrcPort:    12345,
		DstIP:      net.ParseIP("10.0.0.2"),
		DstPort:    80,
		TCPState:   &tcpState,
		BytesIn:    1000,
		BytesOut:   2000,
		PacketsIn:  10,
		PacketsOut: 20,
		StartTS:    now,
		LastSeen:   now,
	}

	// UDP connection
	conn2 := &Connection{
		Timestamp:  now,
		PodName:    "test-pod",
		Namespace:  "test-ns",
		Protocol:   17,
		SrcIP:      net.ParseIP("10.0.0.1"),
		SrcPort:    53,
		DstIP:      net.ParseIP("10.0.0.2"),
		DstPort:    53,
		BytesIn:    500,
		BytesOut:   1000,
		PacketsIn:  5,
		PacketsOut: 10,
		StartTS:    now,
		LastSeen:   now,
	}

	err := store.InsertConnection(ctx, conn1)
	require.NoError(t, err)

	err = store.InsertConnection(ctx, conn2)
	require.NoError(t, err)

	// Get stats
	stats, err := store.GetConnectionStats(ctx, "test-ns", "test-pod", now.Add(-time.Hour), now.Add(time.Hour))
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Verify stats
	assert.Equal(t, int64(2), stats.TotalConnections)
	assert.Equal(t, int64(1500), stats.TotalBytesIn)
	assert.Equal(t, int64(3000), stats.TotalBytesOut)
	assert.Equal(t, int64(15), stats.TotalPacketsIn)
	assert.Equal(t, int64(30), stats.TotalPacketsOut)
	assert.Equal(t, int32(1), stats.TCPConnections)
	assert.Equal(t, int32(1), stats.UDPConnections)
}
