package ebpf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	conntrackv1alpha1 "github.com/vobbilis/codegen/visual/pkg/apis/conntrack/v1alpha1"
)

func TestConvertFilter(t *testing.T) {
	tests := []struct {
		name    string
		filter  conntrackv1alpha1.IPFilter
		want    *FilterRule
		wantErr bool
	}{
		{
			name: "valid tcp filter",
			filter: conntrackv1alpha1.IPFilter{
				Name:            "test-filter",
				SourceCIDR:      "10.0.0.0/8",
				DestinationCIDR: "192.168.0.0/16",
				Ports: []conntrackv1alpha1.PortRange{
					{Start: 80, End: 80},
				},
				Protocol: "tcp",
				Action:   "allow",
			},
			want: &FilterRule{
				SrcIP:    [4]uint32{0x0A000000},
				SrcMask:  [4]uint32{0xFF000000},
				DstIP:    [4]uint32{0xC0A80000},
				DstMask:  [4]uint32{0xFFFF0000},
				PortMin:  80,
				PortMax:  80,
				Protocol: 6, // TCP
				Action:   1, // Allow
			},
			wantErr: false,
		},
		{
			name: "valid udp filter",
			filter: conntrackv1alpha1.IPFilter{
				Name:       "test-udp",
				SourceCIDR: "10.0.0.0/24",
				Ports: []conntrackv1alpha1.PortRange{
					{Start: 53, End: 53},
				},
				Protocol: "udp",
				Action:   "deny",
			},
			want: &FilterRule{
				SrcIP:    [4]uint32{0x0A000000},
				SrcMask:  [4]uint32{0xFFFFFF00},
				PortMin:  53,
				PortMax:  53,
				Protocol: 17, // UDP
				Action:   0,  // Deny
			},
			wantErr: false,
		},
		{
			name: "invalid CIDR",
			filter: conntrackv1alpha1.IPFilter{
				Name:       "invalid-cidr",
				SourceCIDR: "300.0.0.0/8", // Invalid IP
				Protocol:   "tcp",
				Action:     "allow",
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			filter: conntrackv1alpha1.IPFilter{
				Name:       "invalid-protocol",
				SourceCIDR: "10.0.0.0/8",
				Protocol:   "invalid",
				Action:     "allow",
			},
			wantErr: true,
		},
		{
			name: "invalid action",
			filter: conntrackv1alpha1.IPFilter{
				Name:       "invalid-action",
				SourceCIDR: "10.0.0.0/8",
				Protocol:   "tcp",
				Action:     "invalid",
			},
			wantErr: true,
		},
	}

	updater := &MapUpdater{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := updater.convertFilter(tt.filter)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUpdateFilters(t *testing.T) {
	// Create a test config
	config := &conntrackv1alpha1.ConntrackConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-config",
			Namespace: "default",
		},
		Spec: conntrackv1alpha1.ConntrackConfigSpec{
			DefaultAction:  "deny",
			MaxConnections: 10000,
			IPFilters: []conntrackv1alpha1.IPFilter{
				{
					Name:            "allow-internal",
					SourceCIDR:      "10.0.0.0/8",
					DestinationCIDR: "10.0.0.0/8",
					Ports: []conntrackv1alpha1.PortRange{
						{Start: 80, End: 80},
						{Start: 443, End: 443},
					},
					Protocol: "tcp",
					Action:   "allow",
				},
				{
					Name: "allow-dns",
					Ports: []conntrackv1alpha1.PortRange{
						{Start: 53, End: 53},
					},
					Protocol: "both",
					Action:   "allow",
				},
			},
		},
	}

	// Create a mock map updater
	updater := &MapUpdater{
		filterMap: &mockMap{},
	}

	// Test updating filters
	err := updater.UpdateFilters(config)
	require.NoError(t, err)
}

// mockMap implements a mock eBPF map for testing
type mockMap struct {
	data map[uint32]*FilterRule
}

func (m *mockMap) Clear() error {
	m.data = make(map[uint32]*FilterRule)
	return nil
}

func (m *mockMap) Put(key uint32, value interface{}) error {
	if m.data == nil {
		m.data = make(map[uint32]*FilterRule)
	}
	rule, ok := value.(*FilterRule)
	if !ok {
		return fmt.Errorf("invalid value type")
	}
	m.data[key] = rule
	return nil
}

func (m *mockMap) Close() error {
	return nil
}
