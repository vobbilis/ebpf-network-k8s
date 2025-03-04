package database

import (
	"database/sql/driver"
	"fmt"
	"net"
	"time"

	"gorm.io/gorm"
)

// GormConnection represents a network connection in the database using GORM
type GormConnection struct {
	ID        int64     `gorm:"primaryKey;autoIncrement"`
	Timestamp time.Time `gorm:"index;not null;default:CURRENT_TIMESTAMP"`

	// Connection Identity
	PodName     string `gorm:"type:varchar(255);index"`
	Namespace   string `gorm:"type:varchar(255);index"`
	ContainerID string `gorm:"type:varchar(64)"`

	// Network Info
	Protocol int    `gorm:"not null;index"`
	SrcIP    IPAddr `gorm:"type:inet;not null;index"`
	SrcPort  int    `gorm:"not null;index"`
	DstIP    IPAddr `gorm:"type:inet;not null;index"`
	DstPort  int    `gorm:"not null;index"`

	// TCP State
	TCPState        *int   `gorm:"type:smallint"`
	Retransmits     *int   `gorm:"type:integer"`
	RetransmitBytes *int   `gorm:"type:integer"`
	LastRetransTS   *int64 `gorm:"type:bigint"`
	RTTUsec         *int   `gorm:"type:integer"`
	WindowSize      *int   `gorm:"type:integer"`

	// UDP State
	UDPRxDropped *int `gorm:"type:integer"`
	UDPTxDropped *int `gorm:"type:integer"`

	// Conntrack Info
	CTState  *int    `gorm:"type:integer"`
	CTZone   *int    `gorm:"type:integer"`
	CTMark   *int    `gorm:"type:integer"`
	CTLabels []byte  `gorm:"type:bytea"`
	NatIP    *IPAddr `gorm:"type:inet"`
	NatPort  *int    `gorm:"type:integer"`

	// Metrics
	BytesIn    int64 `gorm:"not null;default:0"`
	BytesOut   int64 `gorm:"not null;default:0"`
	PacketsIn  int64 `gorm:"not null;default:0"`
	PacketsOut int64 `gorm:"not null;default:0"`

	// Timestamps
	StartTS  time.Time `gorm:"not null"`
	LastSeen time.Time `gorm:"index;not null"`
}

// TableName specifies the table name for GormConnection
func (GormConnection) TableName() string {
	return "connections"
}

// BeforeCreate hook for GormConnection
func (c *GormConnection) BeforeCreate(tx *gorm.DB) error {
	if c.Timestamp.IsZero() {
		c.Timestamp = time.Now()
	}
	return nil
}

// IPAddr is a custom type for handling net.IP in GORM
type IPAddr net.IP

// Scan implements the sql.Scanner interface
func (ip *IPAddr) Scan(value interface{}) error {
	if value == nil {
		*ip = nil
		return nil
	}

	switch v := value.(type) {
	case string:
		*ip = IPAddr(net.ParseIP(v))
		return nil
	case []byte:
		*ip = IPAddr(net.IP(v))
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into IPAddr", value)
	}
}

// Value implements the driver.Valuer interface
func (ip IPAddr) Value() (driver.Value, error) {
	if ip == nil {
		return nil, nil
	}
	return net.IP(ip).String(), nil
}

// ToNetIP converts IPAddr to net.IP
func (ip IPAddr) ToNetIP() net.IP {
	return net.IP(ip)
}

// FromNetIP converts net.IP to IPAddr
func FromNetIP(ip net.IP) IPAddr {
	return IPAddr(ip)
}

// GormConnectionStats represents aggregated connection statistics
type GormConnectionStats struct {
	BucketTime       time.Time
	TotalConnections int64
	TotalBytesIn     int64
	TotalBytesOut    int64
	TotalPacketsIn   int64
	TotalPacketsOut  int64
	TCPConnections   int32
	UDPConnections   int32
}

// Convert converts a GormConnection to a Connection
func (c *GormConnection) Convert() *Connection {
	return &Connection{
		ID:           c.ID,
		Timestamp:    c.Timestamp,
		PodName:      c.PodName,
		Namespace:    c.Namespace,
		ContainerID:  c.ContainerID,
		Protocol:     c.Protocol,
		SrcIP:        c.SrcIP.ToNetIP(),
		SrcPort:      c.SrcPort,
		DstIP:        c.DstIP.ToNetIP(),
		DstPort:      c.DstPort,
		TCPState:     c.TCPState,
		Retransmits:  c.Retransmits,
		RTTUsec:      c.RTTUsec,
		WindowSize:   c.WindowSize,
		UDPRxDropped: c.UDPRxDropped,
		UDPTxDropped: c.UDPTxDropped,
		CTState:      c.CTState,
		CTZone:       c.CTZone,
		CTMark:       c.CTMark,
		CTLabels:     c.CTLabels,
		NatIP:        c.NatIP.ToNetIPPtr(),
		NatPort:      c.NatPort,
		BytesIn:      c.BytesIn,
		BytesOut:     c.BytesOut,
		PacketsIn:    c.PacketsIn,
		PacketsOut:   c.PacketsOut,
		StartTS:      c.StartTS,
		LastSeen:     c.LastSeen,
	}
}

// FromConnection converts a Connection to a GormConnection
func FromConnection(c *Connection) *GormConnection {
	return &GormConnection{
		ID:           c.ID,
		Timestamp:    c.Timestamp,
		PodName:      c.PodName,
		Namespace:    c.Namespace,
		ContainerID:  c.ContainerID,
		Protocol:     c.Protocol,
		SrcIP:        FromNetIP(c.SrcIP),
		SrcPort:      c.SrcPort,
		DstIP:        FromNetIP(c.DstIP),
		DstPort:      c.DstPort,
		TCPState:     c.TCPState,
		Retransmits:  c.Retransmits,
		RTTUsec:      c.RTTUsec,
		WindowSize:   c.WindowSize,
		UDPRxDropped: c.UDPRxDropped,
		UDPTxDropped: c.UDPTxDropped,
		CTState:      c.CTState,
		CTZone:       c.CTZone,
		CTMark:       c.CTMark,
		CTLabels:     c.CTLabels,
		NatIP:        FromNetIPPtr(c.NatIP),
		NatPort:      c.NatPort,
		BytesIn:      c.BytesIn,
		BytesOut:     c.BytesOut,
		PacketsIn:    c.PacketsIn,
		PacketsOut:   c.PacketsOut,
		StartTS:      c.StartTS,
		LastSeen:     c.LastSeen,
	}
}

// ToNetIPPtr converts *IPAddr to *net.IP
func (ip *IPAddr) ToNetIPPtr() *net.IP {
	if ip == nil {
		return nil
	}
	netIP := net.IP(*ip)
	return &netIP
}

// FromNetIPPtr converts *net.IP to *IPAddr
func FromNetIPPtr(ip *net.IP) *IPAddr {
	if ip == nil {
		return nil
	}
	ipAddr := IPAddr(*ip)
	return &ipAddr
}
