package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConntrackConfig is the Schema for the connection tracking configuration
type ConntrackConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConntrackConfigSpec   `json:"spec,omitempty"`
	Status ConntrackConfigStatus `json:"status,omitempty"`
}

// ConntrackConfigSpec defines the desired state of connection tracking
type ConntrackConfigSpec struct {
	// IPFilters defines the IP filtering rules
	IPFilters []IPFilter `json:"ipFilters"`

	// DefaultAction specifies what to do with connections that don't match any filter
	// +kubebuilder:validation:Enum=allow;deny
	DefaultAction string `json:"defaultAction"`

	// MaxConnections specifies the maximum number of connections to track
	// +kubebuilder:validation:Minimum=1000
	// +kubebuilder:validation:Maximum=10000000
	MaxConnections int32 `json:"maxConnections"`
}

// IPFilter defines a single IP filtering rule
type IPFilter struct {
	// Name is a unique identifier for this filter
	Name string `json:"name"`

	// SourceCIDR specifies the source IP range to match
	// +optional
	SourceCIDR string `json:"sourceCIDR,omitempty"`

	// DestinationCIDR specifies the destination IP range to match
	// +optional
	DestinationCIDR string `json:"destinationCIDR,omitempty"`

	// Ports specifies the ports to match
	// +optional
	Ports []PortRange `json:"ports,omitempty"`

	// Protocol specifies the protocol to match (tcp, udp, or both)
	// +kubebuilder:validation:Enum=tcp;udp;both
	Protocol string `json:"protocol"`

	// Action specifies what to do with matching connections
	// +kubebuilder:validation:Enum=allow;deny
	Action string `json:"action"`
}

// PortRange defines a range of ports
type PortRange struct {
	// Start is the first port in the range
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Start int32 `json:"start"`

	// End is the last port in the range (inclusive)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	End int32 `json:"end"`
}

// ConntrackConfigStatus defines the observed state of connection tracking
type ConntrackConfigStatus struct {
	// ActiveConnections is the current number of tracked connections
	ActiveConnections int32 `json:"activeConnections"`

	// TotalConnectionsSeen is the total number of connections observed
	TotalConnectionsSeen uint64 `json:"totalConnectionsSeen"`

	// TotalConnectionsTracked is the number of connections actually tracked
	TotalConnectionsTracked uint64 `json:"totalConnectionsTracked"`

	// DroppedConnections is the number of connections dropped due to errors or limits
	DroppedConnections uint64 `json:"droppedConnections"`

	// FilteredConnections is the number of connections filtered by rules
	FilteredConnections uint64 `json:"filteredConnections"`

	// PerformanceMetrics contains detailed performance statistics
	PerformanceMetrics ConnectionMetrics `json:"performanceMetrics"`

	// LastUpdated is the timestamp of the last configuration update
	LastUpdated metav1.Time `json:"lastUpdated"`

	// Conditions represent the latest available observations of the config's state
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ConnectionMetrics contains detailed performance metrics
type ConnectionMetrics struct {
	// TCP connection metrics
	TCPStats TCPMetrics `json:"tcpStats"`

	// UDP connection metrics
	UDPStats UDPMetrics `json:"udpStats"`

	// Filter metrics
	FilterStats FilterMetrics `json:"filterStats"`
}

// TCPMetrics contains TCP-specific metrics
type TCPMetrics struct {
	// Total TCP connections seen
	TotalConnections uint64 `json:"totalConnections"`

	// Active TCP connections
	ActiveConnections uint32 `json:"activeConnections"`

	// TCP connections in each state
	StateStats map[string]uint32 `json:"stateStats"`

	// Retransmission statistics
	RetransmitCount uint64 `json:"retransmitCount"`
	RetransmitBytes uint64 `json:"retransmitBytes"`
}

// UDPMetrics contains UDP-specific metrics
type UDPMetrics struct {
	// Total UDP flows seen
	TotalFlows uint64 `json:"totalFlows"`

	// Active UDP flows
	ActiveFlows uint32 `json:"activeFlows"`

	// UDP errors encountered
	ErrorCount uint64 `json:"errorCount"`
}

// FilterMetrics contains filter-related metrics
type FilterMetrics struct {
	// Total connections checked against filters
	TotalChecked uint64 `json:"totalChecked"`

	// Connections allowed by filters
	Allowed uint64 `json:"allowed"`

	// Connections denied by filters
	Denied uint64 `json:"denied"`

	// Per-rule match statistics
	RuleStats map[string]uint64 `json:"ruleStats"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConntrackConfigList contains a list of ConntrackConfig
type ConntrackConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConntrackConfig `json:"items"`
}

// ConnKey represents a connection key in the BPF map
type ConnKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	PodID    uint32
}

// ConnInfo represents connection information in the BPF map
type ConnInfo struct {
	RxBytes         uint64
	TxBytes         uint64
	RxPackets       uint64
	TxPackets       uint64
	RetransmitBytes uint64
	LastRetransTs   uint64
	State           uint8
	LastUpdate      uint64
}
