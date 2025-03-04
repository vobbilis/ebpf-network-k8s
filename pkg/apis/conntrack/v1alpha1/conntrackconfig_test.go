package v1alpha1

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConntrackConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *ConntrackConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ConntrackConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-config",
					Namespace: "default",
				},
				Spec: ConntrackConfigSpec{
					DefaultAction:  "deny",
					MaxConnections: 10000,
					IPFilters: []IPFilter{
						{
							Name:            "allow-internal",
							SourceCIDR:      "10.0.0.0/8",
							DestinationCIDR: "10.0.0.0/8",
							Ports: []PortRange{
								{Start: 80, End: 80},
								{Start: 443, End: 443},
							},
							Protocol: "tcp",
							Action:   "allow",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid port range",
			config: &ConntrackConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-config",
					Namespace: "default",
				},
				Spec: ConntrackConfigSpec{
					DefaultAction:  "deny",
					MaxConnections: 10000,
					IPFilters: []IPFilter{
						{
							Name:       "invalid-ports",
							SourceCIDR: "10.0.0.0/8",
							Ports: []PortRange{
								{Start: 80, End: 79}, // Invalid: start > end
							},
							Protocol: "tcp",
							Action:   "allow",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid CIDR",
			config: &ConntrackConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-config",
					Namespace: "default",
				},
				Spec: ConntrackConfigSpec{
					DefaultAction:  "deny",
					MaxConnections: 10000,
					IPFilters: []IPFilter{
						{
							Name:       "invalid-cidr",
							SourceCIDR: "300.0.0.0/8", // Invalid IP
							Protocol:   "tcp",
							Action:     "allow",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			config: &ConntrackConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-config",
					Namespace: "default",
				},
				Spec: ConntrackConfigSpec{
					DefaultAction:  "deny",
					MaxConnections: 10000,
					IPFilters: []IPFilter{
						{
							Name:       "invalid-protocol",
							SourceCIDR: "10.0.0.0/8",
							Protocol:   "invalid", // Invalid protocol
							Action:     "allow",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid action",
			config: &ConntrackConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-config",
					Namespace: "default",
				},
				Spec: ConntrackConfigSpec{
					DefaultAction:  "invalid", // Invalid action
					MaxConnections: 10000,
					IPFilters: []IPFilter{
						{
							Name:       "test-filter",
							SourceCIDR: "10.0.0.0/8",
							Protocol:   "tcp",
							Action:     "allow",
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a validator
			validator := &ConntrackConfigValidator{}

			// Validate the config
			err := validator.validateConfig(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function to validate config (simulating webhook validation)
func (v *ConntrackConfigValidator) validateConfig(config *ConntrackConfig) error {
	// Validate default action
	if config.Spec.DefaultAction != "allow" && config.Spec.DefaultAction != "deny" {
		return fmt.Errorf("invalid default action: %s", config.Spec.DefaultAction)
	}

	// Validate IP filters
	for _, filter := range config.Spec.IPFilters {
		// Validate source CIDR if specified
		if filter.SourceCIDR != "" {
			if _, _, err := net.ParseCIDR(filter.SourceCIDR); err != nil {
				return fmt.Errorf("invalid source CIDR %s in filter %s: %v",
					filter.SourceCIDR, filter.Name, err)
			}
		}

		// Validate destination CIDR if specified
		if filter.DestinationCIDR != "" {
			if _, _, err := net.ParseCIDR(filter.DestinationCIDR); err != nil {
				return fmt.Errorf("invalid destination CIDR %s in filter %s: %v",
					filter.DestinationCIDR, filter.Name, err)
			}
		}

		// Validate port ranges
		for _, portRange := range filter.Ports {
			if portRange.Start > portRange.End {
				return fmt.Errorf("invalid port range %d-%d in filter %s: start port must be less than or equal to end port",
					portRange.Start, portRange.End, filter.Name)
			}
		}

		// Validate protocol
		if filter.Protocol != "tcp" && filter.Protocol != "udp" && filter.Protocol != "both" {
			return fmt.Errorf("invalid protocol %s in filter %s", filter.Protocol, filter.Name)
		}

		// Validate action
		if filter.Action != "allow" && filter.Action != "deny" {
			return fmt.Errorf("invalid action %s in filter %s", filter.Action, filter.Name)
		}
	}

	return nil
}
