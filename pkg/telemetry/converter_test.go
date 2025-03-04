package telemetry

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vobbilis/codegen/visual/pkg/database"
	pb "github.com/vobbilis/codegen/visual/pkg/telemetry/v1"
)

func TestConvertConnection(t *testing.T) {
	now := time.Now()
	tcpState := 1
	retransmits := 2
	rttUsec := 1000
	windowSize := 65535

	conn := &database.Connection{
		Timestamp:   now,
		PodName:     "test-pod",
		Namespace:   "test-ns",
		ContainerID: "test-container",
		Protocol:    6,
		SrcIP:       net.ParseIP("10.0.0.1"),
		SrcPort:     12345,
		DstIP:       net.ParseIP("10.0.0.2"),
		DstPort:     80,
		TCPState:    &tcpState,
		Retransmits: &retransmits,
		RTTUsec:     &rttUsec,
		WindowSize:  &windowSize,
		BytesIn:     1000,
		BytesOut:    2000,
		PacketsIn:   10,
		PacketsOut:  20,
		StartTS:     now,
		LastSeen:    now,
	}

	event := ConvertConnection(conn, pb.EventType_EVENT_TYPE_NEW_TCP)

	assert.Equal(t, conn.PodName, event.PodName)
	assert.Equal(t, conn.Namespace, event.Namespace)
	assert.Equal(t, conn.ContainerID, event.ContainerId)

	assert.Equal(t, conn.SrcIP, event.Connection.SrcIp)
	assert.Equal(t, conn.DstIP, event.Connection.DstIp)
	assert.Equal(t, uint32(conn.SrcPort), event.Connection.SrcPort)
	assert.Equal(t, uint32(conn.DstPort), event.Connection.DstPort)
	assert.Equal(t, pb.Protocol(conn.Protocol), event.Connection.Protocol)

	assert.Equal(t, pb.TCPState(tcpState), event.Info.TcpState)
	assert.Equal(t, uint32(retransmits), event.Info.Retransmits)
	assert.Equal(t, uint32(rttUsec), event.Info.RttUsec)
	assert.Equal(t, uint32(windowSize), event.Info.WindowSize)

	assert.Equal(t, conn.BytesIn, event.Info.BytesIn)
	assert.Equal(t, conn.BytesOut, event.Info.BytesOut)
	assert.Equal(t, conn.PacketsIn, event.Info.PacketsIn)
	assert.Equal(t, conn.PacketsOut, event.Info.PacketsOut)

	assert.Equal(t, pb.EventType_EVENT_TYPE_NEW_TCP, event.Type)
}

func TestConvertStats(t *testing.T) {
	now := time.Now()
	stats := &database.ConnectionStats{
		BucketTime:       now,
		TotalConnections: 100,
		TotalBytesIn:     1000,
		TotalBytesOut:    2000,
		TotalPacketsIn:   10,
		TotalPacketsOut:  20,
		TCPConnections:   60,
		UDPConnections:   40,
	}

	pbStats := ConvertStats(stats)

	assert.Equal(t, stats.TotalConnections, pbStats.Stats.TotalConnections)
	assert.Equal(t, stats.TotalBytesIn, pbStats.Stats.TotalBytesIn)
	assert.Equal(t, stats.TotalBytesOut, pbStats.Stats.TotalBytesOut)
	assert.Equal(t, stats.TotalPacketsIn, pbStats.Stats.TotalPacketsIn)
	assert.Equal(t, stats.TotalPacketsOut, pbStats.Stats.TotalPacketsOut)
	assert.Equal(t, stats.TCPConnections, pbStats.Stats.TcpConnections)
	assert.Equal(t, stats.UDPConnections, pbStats.Stats.UdpConnections)
}

func TestSafeDeref(t *testing.T) {
	val := 42
	ptr := &val

	assert.Equal(t, 42, safeDeref(ptr))
	assert.Equal(t, 0, safeDeref[int](nil))

	str := "test"
	strPtr := &str

	assert.Equal(t, "test", safeDeref(strPtr))
	assert.Equal(t, "", safeDeref[string](nil))
}

func TestNatIP(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	ipPtr := &ip

	assert.Equal(t, []byte(ip), natIP(ipPtr))
	assert.Nil(t, natIP(nil))
}
