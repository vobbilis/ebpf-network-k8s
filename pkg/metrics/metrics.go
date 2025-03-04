package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ActiveConnections tracks the current number of active connections
	ActiveConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "conntrack_active_connections",
		Help: "Current number of active connections",
	}, []string{"namespace", "config_name"})

	// TotalConnections tracks the total number of connections seen
	TotalConnections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "conntrack_total_connections",
		Help: "Total number of connections processed",
	}, []string{"namespace", "config_name", "action"})

	// FilterMatches tracks the number of times each filter rule was matched
	FilterMatches = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "conntrack_filter_matches",
		Help: "Number of times each filter rule was matched",
	}, []string{"namespace", "config_name", "filter_name", "action"})

	// BytesTransferred tracks the total bytes transferred
	BytesTransferred = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "conntrack_bytes_transferred",
		Help: "Total bytes transferred through tracked connections",
	}, []string{"namespace", "config_name", "direction"})

	// ConnectionErrors tracks connection-related errors
	ConnectionErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "conntrack_errors_total",
		Help: "Total number of connection tracking errors",
	}, []string{"namespace", "config_name", "error_type"})

	// ConfigurationUpdates tracks configuration update events
	ConfigurationUpdates = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "conntrack_config_updates_total",
		Help: "Total number of configuration updates",
	}, []string{"namespace", "config_name", "status"})

	// RuleProcessingDuration tracks the time taken to process filter rules
	RuleProcessingDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "conntrack_rule_processing_duration_seconds",
		Help:    "Time taken to process filter rules",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
	}, []string{"namespace", "config_name"})
)

// MetricsCollector handles metrics collection for connection tracking
type MetricsCollector struct {
	namespace  string
	configName string
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(namespace, configName string) *MetricsCollector {
	return &MetricsCollector{
		namespace:  namespace,
		configName: configName,
	}
}

// RecordActiveConnections updates the active connections metric
func (m *MetricsCollector) RecordActiveConnections(count float64) {
	ActiveConnections.WithLabelValues(m.namespace, m.configName).Set(count)
}

// RecordNewConnection increments the total connections counter
func (m *MetricsCollector) RecordNewConnection(action string) {
	TotalConnections.WithLabelValues(m.namespace, m.configName, action).Inc()
}

// RecordFilterMatch increments the filter match counter
func (m *MetricsCollector) RecordFilterMatch(filterName, action string) {
	FilterMatches.WithLabelValues(m.namespace, m.configName, filterName, action).Inc()
}

// RecordBytesTransferred updates the bytes transferred counter
func (m *MetricsCollector) RecordBytesTransferred(direction string, bytes float64) {
	BytesTransferred.WithLabelValues(m.namespace, m.configName, direction).Add(bytes)
}

// RecordError increments the error counter
func (m *MetricsCollector) RecordError(errorType string) {
	ConnectionErrors.WithLabelValues(m.namespace, m.configName, errorType).Inc()
}

// RecordConfigUpdate increments the configuration update counter
func (m *MetricsCollector) RecordConfigUpdate(status string) {
	ConfigurationUpdates.WithLabelValues(m.namespace, m.configName, status).Inc()
}

// ObserveRuleProcessingDuration records the time taken to process rules
func (m *MetricsCollector) ObserveRuleProcessingDuration(duration float64) {
	RuleProcessingDuration.WithLabelValues(m.namespace, m.configName).Observe(duration)
}
