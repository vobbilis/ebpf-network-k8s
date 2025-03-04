package webhook

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	conntrackv1alpha1 "github.com/vobbilis/codegen/visual/pkg/apis/conntrack/v1alpha1"
)

// +kubebuilder:webhook:path=/validate-conntrack-vobbilis-io-v1alpha1-conntrackconfig,mutating=false,failurePolicy=fail,groups=conntrack.vobbilis.io,resources=conntrackconfigs,verbs=create;update,versions=v1alpha1,name=vconntrackconfig.kb.io,sideEffects=None,admissionReviewVersions=v1

type ConntrackConfigValidator struct {
	decoder *admission.Decoder
}

func (v *ConntrackConfigValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	config := &conntrackv1alpha1.ConntrackConfig{}
	err := v.decoder.Decode(req, config)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Validate IP filters
	for _, filter := range config.Spec.IPFilters {
		// Validate source CIDR if specified
		if filter.SourceCIDR != "" {
			_, _, err := net.ParseCIDR(filter.SourceCIDR)
			if err != nil {
				return admission.Denied(fmt.Sprintf("invalid source CIDR %s in filter %s: %v",
					filter.SourceCIDR, filter.Name, err))
			}
		}

		// Validate destination CIDR if specified
		if filter.DestinationCIDR != "" {
			_, _, err := net.ParseCIDR(filter.DestinationCIDR)
			if err != nil {
				return admission.Denied(fmt.Sprintf("invalid destination CIDR %s in filter %s: %v",
					filter.DestinationCIDR, filter.Name, err))
			}
		}

		// Validate port ranges
		for _, portRange := range filter.Ports {
			if portRange.Start > portRange.End {
				return admission.Denied(fmt.Sprintf("invalid port range %d-%d in filter %s: start port must be less than or equal to end port",
					portRange.Start, portRange.End, filter.Name))
			}
		}
	}

	// Validate default action
	if config.Spec.DefaultAction != "allow" && config.Spec.DefaultAction != "deny" {
		return admission.Denied(fmt.Sprintf("invalid default action %s: must be either 'allow' or 'deny'",
			config.Spec.DefaultAction))
	}

	return admission.Allowed("configuration is valid")
}

func (v *ConntrackConfigValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}
