package telemetry

import (
	"context"
	"net"
	"time"

	"github.com/vobbilis/codegen/visual/pkg/database"
	pb "github.com/vobbilis/codegen/visual/pkg/telemetry/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server implements the ConnectionTracker gRPC service
type Server struct {
	pb.UnimplementedConnectionTrackerServer
	store *database.Store
}

// NewServer creates a new telemetry server
func NewServer(store *database.Store) *Server {
	return &Server{store: store}
}

// StreamConnections implements the StreamConnections RPC
func (s *Server) StreamConnections(req *pb.StreamConnectionsRequest, stream pb.ConnectionTracker_StreamConnectionsServer) error {
	ctx := stream.Context()

	// Create a ticker for periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			// Get latest connections
			connections, err := s.store.GetActiveConnections(ctx, req.Namespace, req.PodName, req.Protocol)
			if err != nil {
				return status.Errorf(codes.Internal, "failed to get connections: %v", err)
			}

			// Stream each connection
			for _, conn := range connections {
				event := convertConnection(conn, pb.EventType_EVENT_TYPE_TCP_UPDATE)
				if err := stream.Send(event); err != nil {
					return status.Errorf(codes.Internal, "failed to send event: %v", err)
				}
			}
		}
	}
}

// GetConnectionStats implements the GetConnectionStats RPC
func (s *Server) GetConnectionStats(ctx context.Context, req *pb.ConnectionStatsRequest) (*pb.ConnectionStats, error) {
	// Get stats from database
	stats, err := s.store.GetConnectionStats(ctx, req.Namespace, req.PodName,
		req.StartTime.AsTime(), req.EndTime.AsTime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get stats: %v", err)
	}

	return convertStats(stats), nil
}

// convertConnection converts a database Connection to a protobuf ConnectionEvent
func convertConnection(conn *database.Connection, eventType pb.EventType) *pb.ConnectionEvent {
	return &pb.ConnectionEvent{
		EventType:       eventType,
		Timestamp:       timestamppb.New(conn.Timestamp),
		PodName:         conn.PodName,
		Namespace:       conn.Namespace,
		ContainerId:     conn.ContainerID,
		Protocol:        int32(conn.Protocol),
		SrcIp:           conn.SrcIP.To4(),
		SrcPort:         int32(conn.SrcPort),
		DstIp:           conn.DstIP.To4(),
		DstPort:         int32(conn.DstPort),
		TcpState:        safeDerefInt32(conn.TCPState),
		Retransmits:     safeDerefInt32(conn.Retransmits),
		RetransmitBytes: safeDerefInt32(conn.RetransmitBytes),
		LastRetransTs:   safeDerefInt64(conn.LastRetransTS),
		RttUsec:         safeDerefInt32(conn.RTTUsec),
		WindowSize:      safeDerefInt32(conn.WindowSize),
		UdpRxDropped:    safeDerefInt32(conn.UDPRxDropped),
		UdpTxDropped:    safeDerefInt32(conn.UDPTxDropped),
		CtState:         safeDerefInt32(conn.CTState),
		CtZone:          safeDerefInt32(conn.CTZone),
		CtMark:          safeDerefInt32(conn.CTMark),
		CtLabels:        conn.CTLabels,
		NatIp:           safeIPBytes(conn.NatIP),
		NatPort:         safeDerefInt32(conn.NatPort),
		BytesIn:         conn.BytesIn,
		BytesOut:        conn.BytesOut,
		PacketsIn:       conn.PacketsIn,
		PacketsOut:      conn.PacketsOut,
		StartTs:         timestamppb.New(conn.StartTS),
		LastSeen:        timestamppb.New(conn.LastSeen),
	}
}

// convertStats converts database ConnectionStats to protobuf ConnectionStats
func convertStats(stats *database.ConnectionStats) *pb.ConnectionStats {
	return &pb.ConnectionStats{
		BucketTime:       timestamppb.New(stats.BucketTime),
		TotalConnections: stats.TotalConnections,
		TotalBytesIn:     stats.TotalBytesIn,
		TotalBytesOut:    stats.TotalBytesOut,
		TotalPacketsIn:   stats.TotalPacketsIn,
		TotalPacketsOut:  stats.TotalPacketsOut,
		TcpConnections:   stats.TCPConnections,
		UdpConnections:   stats.UDPConnections,
	}
}

// safeDerefInt32 safely dereferences a pointer to an int, returning nil if nil
func safeDerefInt32(ptr *int) *int32 {
	if ptr == nil {
		return nil
	}
	val := int32(*ptr)
	return &val
}

// safeIPBytes safely converts a net.IP pointer to bytes, returning nil if nil
func safeIPBytes(ip *net.IP) []byte {
	if ip == nil {
		return nil
	}
	return (*ip).To4()
}

// safeDerefInt64 safely dereferences a pointer to an int64, returning nil if nil
func safeDerefInt64(ptr *int64) *int64 {
	if ptr == nil {
		return nil
	}
	return ptr
}
