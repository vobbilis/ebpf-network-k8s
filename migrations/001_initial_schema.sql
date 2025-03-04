-- Connection tracking schema

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Create the connections table
CREATE TABLE connections (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Connection Identity
    pod_name VARCHAR(255),
    namespace VARCHAR(255),
    container_id VARCHAR(64),
    
    -- Network Info
    protocol INTEGER NOT NULL, -- TCP(6)/UDP(17)
    src_ip INET NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip INET NOT NULL,
    dst_port INTEGER NOT NULL,
    
    -- TCP State (NULL for UDP)
    tcp_state SMALLINT,
    retransmits INTEGER,
    rtt_usec INTEGER,
    window_size INTEGER,
    
    -- UDP State
    udp_rx_dropped INTEGER,
    udp_tx_dropped INTEGER,
    
    -- Conntrack Info
    ct_state INTEGER,
    ct_zone INTEGER,
    ct_mark INTEGER,
    ct_labels BYTEA,
    nat_ip INET,
    nat_port INTEGER,
    
    -- Metrics
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    packets_in BIGINT NOT NULL DEFAULT 0,
    packets_out BIGINT NOT NULL DEFAULT 0,
    
    -- Timestamps
    start_ts TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

-- Create hypertable for time-series data
SELECT create_hypertable('connections', 'timestamp');

-- Create indexes for common queries
CREATE INDEX idx_conn_pod ON connections (namespace, pod_name);
CREATE INDEX idx_conn_ips ON connections (src_ip, dst_ip);
CREATE INDEX idx_conn_ports ON connections (src_port, dst_port);
CREATE INDEX idx_conn_proto ON connections (protocol);
CREATE INDEX idx_conn_last_seen ON connections (last_seen DESC);

-- Create view for active connections
CREATE VIEW active_connections AS
SELECT *
FROM connections
WHERE last_seen > NOW() - INTERVAL '5 minutes';

-- Create materialized view for connection statistics
CREATE MATERIALIZED VIEW connection_stats
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', timestamp) AS bucket,
    namespace,
    pod_name,
    protocol,
    COUNT(*) as total_connections,
    SUM(bytes_in) as total_bytes_in,
    SUM(bytes_out) as total_bytes_out,
    SUM(packets_in) as total_packets_in,
    SUM(packets_out) as total_packets_out,
    COUNT(CASE WHEN protocol = 6 THEN 1 END) as tcp_connections,
    COUNT(CASE WHEN protocol = 17 THEN 1 END) as udp_connections
FROM connections
GROUP BY bucket, namespace, pod_name, protocol
WITH NO DATA;

-- Create refresh policy for materialized view
SELECT add_continuous_aggregate_policy('connection_stats',
    start_offset => INTERVAL '1 hour',
    end_offset => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '5 minutes');

-- Create retention policy
SELECT add_retention_policy('connections',
    INTERVAL '30 days',
    if_not_exists => true);

-- Create compression policy
SELECT add_compression_policy('connections',
    INTERVAL '7 days',
    if_not_exists => true); 