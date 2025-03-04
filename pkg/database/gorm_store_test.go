package database

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestGormDB(t *testing.T) *GormStore {
	ctx := context.Background()
	connString := "postgres://postgres:postgres@localhost:5432/conntrack_test?sslmode=disable"

	// Create test database
	store, err := NewGormStore(ctx, connString)
	require.NoError(t, err)

	return store
}

func TestGormInsertConnection(t *testing.T) {
	store := setupTestGormDB(t)
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
	var count int64
	err = store.db.Model(&GormConnection{}).Count(&count).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestGormUpdateConnection(t *testing.T) {
	store := setupTestGormDB(t)
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
	var gormConn GormConnection
	err = store.db.Where("src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ? AND protocol = ?",
		FromNetIP(conn.SrcIP), FromNetIP(conn.DstIP), conn.SrcPort, conn.DstPort, conn.Protocol).
		First(&gormConn).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(2000), gormConn.BytesIn)
	assert.Equal(t, 2, *gormConn.TCPState)
}

func TestGormGetConnectionStats(t *testing.T) {
	store := setupTestGormDB(t)
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

func TestGormGetActiveConnections(t *testing.T) {
	store := setupTestGormDB(t)
	defer store.Close()

	ctx := context.Background()

	// Insert test data
	now := time.Now()
	tcpState := 1

	// Active TCP connection
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

	// Inactive TCP connection
	conn2 := &Connection{
		Timestamp:  now.Add(-10 * time.Minute),
		PodName:    "test-pod",
		Namespace:  "test-ns",
		Protocol:   6,
		SrcIP:      net.ParseIP("10.0.0.1"),
		SrcPort:    12346,
		DstIP:      net.ParseIP("10.0.0.2"),
		DstPort:    80,
		TCPState:   &tcpState,
		BytesIn:    1000,
		BytesOut:   2000,
		PacketsIn:  10,
		PacketsOut: 20,
		StartTS:    now.Add(-10 * time.Minute),
		LastSeen:   now.Add(-10 * time.Minute),
	}

	err := store.InsertConnection(ctx, conn1)
	require.NoError(t, err)

	err = store.InsertConnection(ctx, conn2)
	require.NoError(t, err)

	// Get active connections
	connections, err := store.GetActiveConnections(ctx, "test-ns", "test-pod", 6)
	assert.NoError(t, err)
	assert.Len(t, connections, 1)

	// Verify active connection
	assert.Equal(t, conn1.SrcIP.String(), connections[0].SrcIP.String())
	assert.Equal(t, conn1.DstIP.String(), connections[0].DstIP.String())
	assert.Equal(t, conn1.SrcPort, connections[0].SrcPort)
	assert.Equal(t, conn1.DstPort, connections[0].DstPort)
}
