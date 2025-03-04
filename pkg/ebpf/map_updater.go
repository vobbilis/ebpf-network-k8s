package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	conntrackv1alpha1 "github.com/vobbilis/codegen/visual/pkg/apis/conntrack/v1alpha1"
)

// FilterRule represents a rule in the eBPF map
type FilterRule struct {
	SrcIP    [4]uint32
	DstIP    [4]uint32
	SrcMask  [4]uint32
	DstMask  [4]uint32
	PortMin  uint16
	PortMax  uint16
	Protocol uint8
	Action   uint8
}

// MapUpdater handles updates to eBPF maps for connection tracking
type MapUpdater struct {
	filterMap *ebpf.Map
}

// NewMapUpdater creates a new MapUpdater instance
func NewMapUpdater(filterMap *ebpf.Map) (*MapUpdater, error) {
	if filterMap == nil {
		return nil, fmt.Errorf("filter map is nil")
	}

	return &MapUpdater{
		filterMap: filterMap,
	}, nil
}

// UpdateFilters updates the eBPF map with new filter rules
func (m *MapUpdater) UpdateFilters(config *conntrackv1alpha1.ConntrackConfig) error {
	// Delete all existing entries
	var key uint32
	for {
		err := m.filterMap.Delete(&key)
		if err != nil {
			if err == ebpf.ErrKeyNotExist {
				break
			}
			return fmt.Errorf("failed to delete filter map entry: %v", err)
		}
		key++
	}

	// Convert and apply each filter rule
	for i, filter := range config.Spec.IPFilters {
		rule, err := m.convertFilter(filter)
		if err != nil {
			return fmt.Errorf("failed to convert filter %s: %v", filter.Name, err)
		}

		err = m.filterMap.Put(uint32(i), rule)
		if err != nil {
			return fmt.Errorf("failed to update filter map for rule %s: %v", filter.Name, err)
		}
	}

	return nil
}

// convertFilter converts a ConntrackConfig filter to an eBPF filter rule
func (m *MapUpdater) convertFilter(filter conntrackv1alpha1.IPFilter) (*FilterRule, error) {
	rule := &FilterRule{}

	// Convert source CIDR
	if filter.SourceCIDR != "" {
		_, ipNet, err := net.ParseCIDR(filter.SourceCIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid source CIDR: %v", err)
		}
		rule.SrcIP[0] = binary.BigEndian.Uint32(ipNet.IP.To4())
		rule.SrcMask[0] = binary.BigEndian.Uint32(ipNet.Mask)
	}

	// Convert destination CIDR
	if filter.DestinationCIDR != "" {
		_, ipNet, err := net.ParseCIDR(filter.DestinationCIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid destination CIDR: %v", err)
		}
		rule.DstIP[0] = binary.BigEndian.Uint32(ipNet.IP.To4())
		rule.DstMask[0] = binary.BigEndian.Uint32(ipNet.Mask)
	}

	// Convert port ranges
	if len(filter.Ports) > 0 {
		rule.PortMin = uint16(filter.Ports[0].Start)
		rule.PortMax = uint16(filter.Ports[0].End)
	}

	// Convert protocol
	switch filter.Protocol {
	case "tcp":
		rule.Protocol = 6
	case "udp":
		rule.Protocol = 17
	case "both":
		rule.Protocol = 0
	default:
		return nil, fmt.Errorf("invalid protocol: %s", filter.Protocol)
	}

	// Convert action
	switch filter.Action {
	case "allow":
		rule.Action = 1
	case "deny":
		rule.Action = 0
	default:
		return nil, fmt.Errorf("invalid action: %s", filter.Action)
	}

	return rule, nil
}

// Close closes the eBPF maps
func (m *MapUpdater) Close() error {
	return m.filterMap.Close()
}
