package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// GormStore handles database operations using GORM
type GormStore struct {
	db *gorm.DB
}

// NewGormStore creates a new GORM-based store
func NewGormStore(ctx context.Context, connString string) (*GormStore, error) {
	config := postgres.Config{
		DSN:                  connString,
		PreferSimpleProtocol: true,
	}

	db, err := gorm.Open(postgres.New(config), &gorm.Config{
		PrepareStmt: true,
		QueryFields: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Enable TimescaleDB extension
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS timescaledb").Error; err != nil {
		return nil, fmt.Errorf("failed to enable TimescaleDB: %w", err)
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(&GormConnection{}); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	// Create hypertable
	if err := db.Exec("SELECT create_hypertable('connections', 'timestamp', if_not_exists => true)").Error; err != nil {
		return nil, fmt.Errorf("failed to create hypertable: %w", err)
	}

	return &GormStore{db: db}, nil
}

// InsertConnection inserts a new connection record
func (s *GormStore) InsertConnection(ctx context.Context, conn *Connection) error {
	gormConn := FromConnection(conn)
	return s.db.WithContext(ctx).Create(gormConn).Error
}

// UpdateConnection updates an existing connection record
func (s *GormStore) UpdateConnection(ctx context.Context, conn *Connection) error {
	gormConn := FromConnection(conn)
	return s.db.WithContext(ctx).
		Where("src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ? AND protocol = ?",
			gormConn.SrcIP, gormConn.DstIP, gormConn.SrcPort, gormConn.DstPort, gormConn.Protocol).
		Updates(map[string]interface{}{
			"tcp_state":      gormConn.TCPState,
			"retransmits":    gormConn.Retransmits,
			"rtt_usec":       gormConn.RTTUsec,
			"window_size":    gormConn.WindowSize,
			"udp_rx_dropped": gormConn.UDPRxDropped,
			"udp_tx_dropped": gormConn.UDPTxDropped,
			"ct_state":       gormConn.CTState,
			"ct_zone":        gormConn.CTZone,
			"ct_mark":        gormConn.CTMark,
			"ct_labels":      gormConn.CTLabels,
			"nat_ip":         gormConn.NatIP,
			"nat_port":       gormConn.NatPort,
			"bytes_in":       gormConn.BytesIn,
			"bytes_out":      gormConn.BytesOut,
			"packets_in":     gormConn.PacketsIn,
			"packets_out":    gormConn.PacketsOut,
			"last_seen":      gormConn.LastSeen,
		}).Error
}

// GetConnectionStats retrieves connection statistics
func (s *GormStore) GetConnectionStats(ctx context.Context, namespace, podName string, start, end time.Time) (*ConnectionStats, error) {
	var stats GormConnectionStats

	err := s.db.WithContext(ctx).Raw(`
		SELECT
			time_bucket('1 minute', timestamp) as bucket_time,
			COUNT(*) as total_connections,
			SUM(bytes_in) as total_bytes_in,
			SUM(bytes_out) as total_bytes_out,
			SUM(packets_in) as total_packets_in,
			SUM(packets_out) as total_packets_out,
			COUNT(CASE WHEN protocol = 6 THEN 1 END) as tcp_connections,
			COUNT(CASE WHEN protocol = 17 THEN 1 END) as udp_connections
		FROM connections
		WHERE
			namespace = ? AND
			pod_name = ? AND
			timestamp BETWEEN ? AND ?
		GROUP BY bucket_time
		ORDER BY bucket_time DESC
		LIMIT 1
	`, namespace, podName, start, end).Scan(&stats).Error

	if err != nil {
		return nil, err
	}

	return &ConnectionStats{
		BucketTime:       stats.BucketTime,
		TotalConnections: stats.TotalConnections,
		TotalBytesIn:     stats.TotalBytesIn,
		TotalBytesOut:    stats.TotalBytesOut,
		TotalPacketsIn:   stats.TotalPacketsIn,
		TotalPacketsOut:  stats.TotalPacketsOut,
		TCPConnections:   stats.TCPConnections,
		UDPConnections:   stats.UDPConnections,
	}, nil
}

// GetActiveConnections retrieves active connections filtered by namespace, pod name, and protocol
func (s *GormStore) GetActiveConnections(ctx context.Context, namespace, podName string, protocol int32) ([]*Connection, error) {
	var gormConns []*GormConnection

	query := s.db.WithContext(ctx).
		Where("last_seen > ?", time.Now().Add(-5*time.Minute)).
		Order("last_seen DESC")

	if namespace != "" {
		query = query.Where("namespace = ?", namespace)
	}
	if podName != "" {
		query = query.Where("pod_name = ?", podName)
	}
	if protocol != 0 {
		query = query.Where("protocol = ?", protocol)
	}

	if err := query.Find(&gormConns).Error; err != nil {
		return nil, err
	}

	connections := make([]*Connection, len(gormConns))
	for i, gormConn := range gormConns {
		connections[i] = gormConn.Convert()
	}

	return connections, nil
}

// Close closes the database connection
func (s *GormStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
