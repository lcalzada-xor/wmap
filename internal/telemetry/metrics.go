package telemetry

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// PacketsCaptured counts total packets received by the sniffer
	PacketsCaptured = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "wmap",
			Name:      "packets_captured_total",
			Help:      "Total number of packets captured by the sniffer",
		},
		[]string{"interface"},
	)

	// PacketsProcessed counts packets successfully processed by the application
	PacketsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "wmap",
			Name:      "packets_processed_total",
			Help:      "Total number of packets processed by the application",
		},
		[]string{"interface"},
	)

	// PacketsDropped counts packets dropped due to buffer full or errors
	PacketsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "wmap",
			Name:      "packets_dropped_total",
			Help:      "Total number of packets dropped",
		},
		[]string{"interface", "reason"},
	)

	// InjectionsTotal counts total injection attempts
	InjectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "wmap",
			Name:      "injection_total",
			Help:      "Total number of packet injection attempts",
		},
		[]string{"interface", "type"},
	)

	// InjectionErrors counts failed injection attempts
	InjectionErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "wmap",
			Name:      "injection_errors_total",
			Help:      "Total number of failed packet injection attempts",
		},
		[]string{"interface", "type"},
	)

	// Ensure metrics are only registered once
	once sync.Once
)

// InitMetrics registers all metrics with the global Prometheus registry
// This function is idempotent and can be called multiple times safely
func InitMetrics() {
	once.Do(func() {
		// Register metrics, ignoring errors if already registered
		// This prevents panics when metrics are already in the registry
		prometheus.DefaultRegisterer.Register(PacketsCaptured)
		prometheus.DefaultRegisterer.Register(PacketsProcessed)
		prometheus.DefaultRegisterer.Register(PacketsDropped)
		prometheus.DefaultRegisterer.Register(InjectionsTotal)
		prometheus.DefaultRegisterer.Register(InjectionErrors)
	})
}
