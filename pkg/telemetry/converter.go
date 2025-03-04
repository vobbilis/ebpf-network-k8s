package telemetry

import (
	"net"

	"github.com/vobbilis/codegen/visual/pkg/database"
	pb "github.com/vobbilis/codegen/visual/pkg/telemetry/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ConvertConnection converts a database Connection to a protobuf ConnectionEvent
func ConvertConnection(conn *database.Connection, eventType pb.EventType) *pb.ConnectionEvent {
	return &pb.ConnectionEvent{
		Timestamp:   timestamppb.New(conn.Timestamp),
		Namespace:   conn.Namespace,
		PodName:     conn.PodName,
		ContainerId: conn.ContainerID,

		Connection: &pb.ConnectionKey{
			SrcIp:    conn.SrcIP,
			DstIp:    conn.DstIP,
			SrcPort:  uint32(conn.SrcPort),
			DstPort:  uint32(conn.DstPort),
			Protocol: pb.Protocol(conn.Protocol),
		},

		Info: &pb.ConnectionInfo{
			TcpState:    pb.TCPState(safeDeref(conn.TCPState)),
			Retransmits: uint32(safeDeref(conn.Retransmits)),
			RttUsec:     uint32(safeDeref(conn.RTTUsec)),
			WindowSize:  uint32(safeDeref(conn.WindowSize)),

			UdpRxDropped: uint32(safeDeref(conn.UDPRxDropped)),
			UdpTxDropped: uint32(safeDeref(conn.UDPTxDropped)),

			CtState:  uint32(safeDeref(conn.CTState)),
			CtZone:   uint32(safeDeref(conn.CTZone)),
			CtMark:   uint32(safeDeref(conn.CTMark)),
			CtLabels: conn.CTLabels,
			NatIp:    natIP(conn.NatIP),
			NatPort:  uint32(safeDeref(conn.NatPort)),

			BytesIn:    conn.BytesIn,
			BytesOut:   conn.BytesOut,
			PacketsIn:  conn.PacketsIn,
			PacketsOut: conn.PacketsOut,

			StartTs:  timestamppb.New(conn.StartTS),
			LastSeen: timestamppb.New(conn.LastSeen),
		},

		Type: eventType,
	}
}

// ConvertStats converts database ConnectionStats to protobuf ConnectionStats
func ConvertStats(stats *database.ConnectionStats) *pb.ConnectionStats {
	return &pb.ConnectionStats{
		Stats: &pb.ConnectionStats_Stats{
			TotalConnections: stats.TotalConnections,
			TotalBytesIn:     stats.TotalBytesIn,
			TotalBytesOut:    stats.TotalBytesOut,
			TotalPacketsIn:   stats.TotalPacketsIn,
			TotalPacketsOut:  stats.TotalPacketsOut,
			TcpConnections:   stats.TCPConnections,
			UdpConnections:   stats.UDPConnections,
		},
		BucketTime: timestamppb.New(stats.BucketTime),
	}
}

// Helper functions

func safeDeref[T any](ptr *T) T {
	if ptr == nil {
		var zero T
		return zero
	}
	return *ptr
}

func natIP(ip *net.IP) []byte {
	if ip == nil {
		return nil
	}
	return *ip
}
