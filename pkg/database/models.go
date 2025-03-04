package database

import (
	"context"
	"net"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
)

// Connection represents a network connection in the database
type Connection struct {
	ID        int64     `db:"id"`
	Timestamp time.Time `db:"timestamp"`

	// Connection Identity
	PodName     string `db:"pod_name"`
	Namespace   string `db:"namespace"`
	ContainerID string `db:"container_id"`

	// Network Info
	Protocol int    `db:"protocol"`
	SrcIP    net.IP `db:"src_ip"`
	SrcPort  int    `db:"src_port"`
	DstIP    net.IP `db:"dst_ip"`
	DstPort  int    `db:"dst_port"`

	// TCP State
	TCPState        *int   `db:"tcp_state"`
	Retransmits     *int   `db:"retransmits"`
	RetransmitBytes *int   `db:"retransmit_bytes"`
	LastRetransTS   *int64 `db:"last_retrans_ts"`
	RTTUsec         *int   `db:"rtt_usec"`
	WindowSize      *int   `db:"window_size"`

	// UDP State
	UDPRxDropped *int `db:"udp_rx_dropped"`
	UDPTxDropped *int `db:"udp_tx_dropped"`

	// Conntrack Info
	CTState  *int    `db:"ct_state"`
	CTZone   *int    `db:"ct_zone"`
	CTMark   *int    `db:"ct_mark"`
	CTLabels []byte  `db:"ct_labels"`
	NatIP    *net.IP `db:"nat_ip"`
	NatPort  *int    `db:"nat_port"`

	// Metrics
	BytesIn    int64 `db:"bytes_in"`
	BytesOut   int64 `db:"bytes_out"`
	PacketsIn  int64 `db:"packets_in"`
	PacketsOut int64 `db:"packets_out"`

	// Timestamps
	StartTS  time.Time `db:"start_ts"`
	LastSeen time.Time `db:"last_seen"`
}

// Store handles database operations
type Store struct {
	db *pgxpool.Pool
}

// NewStore creates a new database store
func NewStore(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.Connect(ctx, connString)
	if err != nil {
		return nil, err
	}

	return &Store{db: pool}, nil
}

// InsertConnection inserts a new connection record
func (s *Store) InsertConnection(ctx context.Context, conn *Connection) error {
	query := `
        INSERT INTO connections (
            timestamp, pod_name, namespace, container_id,
            protocol, src_ip, src_port, dst_ip, dst_port,
            tcp_state, retransmits, retransmit_bytes, last_retrans_ts, rtt_usec, window_size,
            udp_rx_dropped, udp_tx_dropped,
            ct_state, ct_zone, ct_mark, ct_labels, nat_ip, nat_port,
            bytes_in, bytes_out, packets_in, packets_out,
            start_ts, last_seen
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19,
            $20, $21, $22, $23, $24, $25, $26, $27
        )`

	_, err := s.db.Exec(ctx, query,
		conn.Timestamp, conn.PodName, conn.Namespace, conn.ContainerID,
		conn.Protocol, conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort,
		conn.TCPState, conn.Retransmits, conn.RetransmitBytes, conn.LastRetransTS, conn.RTTUsec, conn.WindowSize,
		conn.UDPRxDropped, conn.UDPTxDropped,
		conn.CTState, conn.CTZone, conn.CTMark, conn.CTLabels,
		conn.NatIP, conn.NatPort,
		conn.BytesIn, conn.BytesOut, conn.PacketsIn, conn.PacketsOut,
		conn.StartTS, conn.LastSeen)

	return err
}

// UpdateConnection updates an existing connection record
func (s *Store) UpdateConnection(ctx context.Context, conn *Connection) error {
	query := `
        UPDATE connections SET
            tcp_state = $1,
            retransmits = $2,
            retransmit_bytes = $3,
            last_retrans_ts = $4,
            rtt_usec = $5,
            window_size = $6,
            udp_rx_dropped = $7,
            udp_tx_dropped = $8,
            ct_state = $9,
            ct_zone = $10,
            ct_mark = $11,
            ct_labels = $12,
            nat_ip = $13,
            nat_port = $14,
            bytes_in = $15,
            bytes_out = $16,
            packets_in = $17,
            packets_out = $18,
            last_seen = $19
        WHERE
            src_ip = $20 AND
            dst_ip = $21 AND
            src_port = $22 AND
            dst_port = $23 AND
            protocol = $24`

	_, err := s.db.Exec(ctx, query,
		conn.TCPState, conn.Retransmits, conn.RetransmitBytes, conn.LastRetransTS, conn.RTTUsec, conn.WindowSize,
		conn.UDPRxDropped, conn.UDPTxDropped,
		conn.CTState, conn.CTZone, conn.CTMark, conn.CTLabels,
		conn.NatIP, conn.NatPort,
		conn.BytesIn, conn.BytesOut, conn.PacketsIn, conn.PacketsOut,
		conn.LastSeen,
		conn.SrcIP, conn.DstIP, conn.SrcPort, conn.DstPort, conn.Protocol)

	return err
}

// GetConnectionStats retrieves connection statistics
func (s *Store) GetConnectionStats(ctx context.Context, namespace, podName string, start, end time.Time) (*ConnectionStats, error) {
	query := `
        SELECT
            time_bucket('1 minute', timestamp) as bucket,
            COUNT(*) as total_connections,
            SUM(bytes_in) as total_bytes_in,
            SUM(bytes_out) as total_bytes_out,
            SUM(packets_in) as total_packets_in,
            SUM(packets_out) as total_packets_out,
            COUNT(CASE WHEN protocol = 6 THEN 1 END) as tcp_connections,
            COUNT(CASE WHEN protocol = 17 THEN 1 END) as udp_connections
        FROM connections
        WHERE
            namespace = $1 AND
            pod_name = $2 AND
            timestamp BETWEEN $3 AND $4
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT 1`

	var stats ConnectionStats
	err := s.db.QueryRow(ctx, query, namespace, podName, start, end).Scan(
		&stats.BucketTime,
		&stats.TotalConnections,
		&stats.TotalBytesIn,
		&stats.TotalBytesOut,
		&stats.TotalPacketsIn,
		&stats.TotalPacketsOut,
		&stats.TCPConnections,
		&stats.UDPConnections,
	)

	if err != nil {
		return nil, err
	}

	return &stats, nil
}

// ConnectionStats represents aggregated connection statistics
type ConnectionStats struct {
	BucketTime       time.Time
	TotalConnections int64
	TotalBytesIn     int64
	TotalBytesOut    int64
	TotalPacketsIn   int64
	TotalPacketsOut  int64
	TCPConnections   int32
	UDPConnections   int32
}

// GetActiveConnections retrieves active connections filtered by namespace, pod name, and protocol
func (s *Store) GetActiveConnections(ctx context.Context, namespace, podName string, protocol int32) ([]*Connection, error) {
	query := `
        SELECT 
            id, timestamp, pod_name, namespace, container_id,
            protocol, src_ip, src_port, dst_ip, dst_port,
            tcp_state, retransmits, retransmit_bytes, last_retrans_ts, rtt_usec, window_size,
            udp_rx_dropped, udp_tx_dropped,
            ct_state, ct_zone, ct_mark, ct_labels, nat_ip, nat_port,
            bytes_in, bytes_out, packets_in, packets_out,
            start_ts, last_seen
        FROM connections
        WHERE ($1 = '' OR namespace = $1)
        AND ($2 = '' OR pod_name = $2)
        AND ($3 = 0 OR protocol = $3)
        AND last_seen > NOW() - INTERVAL '5 minutes'
        ORDER BY last_seen DESC`

	rows, err := s.db.Query(ctx, query, namespace, podName, protocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []*Connection
	for rows.Next() {
		conn := &Connection{}
		err := rows.Scan(
			&conn.ID, &conn.Timestamp, &conn.PodName, &conn.Namespace, &conn.ContainerID,
			&conn.Protocol, &conn.SrcIP, &conn.SrcPort, &conn.DstIP, &conn.DstPort,
			&conn.TCPState, &conn.Retransmits, &conn.RetransmitBytes, &conn.LastRetransTS, &conn.RTTUsec, &conn.WindowSize,
			&conn.UDPRxDropped, &conn.UDPTxDropped,
			&conn.CTState, &conn.CTZone, &conn.CTMark, &conn.CTLabels, &conn.NatIP, &conn.NatPort,
			&conn.BytesIn, &conn.BytesOut, &conn.PacketsIn, &conn.PacketsOut,
			&conn.StartTS, &conn.LastSeen,
		)
		if err != nil {
			return nil, err
		}
		connections = append(connections, conn)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return connections, nil
}

// Close closes the database connection
func (s *Store) Close() {
	s.db.Close()
}
