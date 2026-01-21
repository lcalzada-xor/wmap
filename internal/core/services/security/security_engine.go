package security

import (
	"context"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// SecurityEngine analyzes network security state using pluggable detectors.
type SecurityEngine struct {
	Registry  ports.DeviceRegistry
	detectors []Detector
	rules     []domain.AlertRule
	alerts    []domain.Alert
	mu        sync.RWMutex
}

// NewSecurityEngine creates a new security engine with default detectors.
func NewSecurityEngine(registry ports.DeviceRegistry) *SecurityEngine {
	engine := &SecurityEngine{
		Registry: registry,
		rules:    make([]domain.AlertRule, 0),
		alerts:   make([]domain.Alert, 0),
	}

	// Register default detectors
	engine.detectors = []Detector{
		&RetryRateDetector{},
		&KarmaDetector{},
		&EvilTwinDetector{},
		&SpoofingDetector{},
		&RuleDetector{engine: engine},
	}

	return engine
}

// AddDetector registers a new detector plugin.
func (se *SecurityEngine) AddDetector(detector Detector) {
	se.mu.Lock()
	defer se.mu.Unlock()
	se.detectors = append(se.detectors, detector)
}

// AddRule adds a new alert rule.
func (se *SecurityEngine) AddRule(ctx context.Context, rule domain.AlertRule) {
	se.mu.Lock()
	defer se.mu.Unlock()
	se.rules = append(se.rules, rule)
}

// GetAlerts returns all active alerts.
func (se *SecurityEngine) GetAlerts(ctx context.Context) []domain.Alert {
	se.mu.RLock()
	defer se.mu.RUnlock()
	result := make([]domain.Alert, len(se.alerts))
	copy(result, se.alerts)
	return result
}

// Analyze inspects a device for anomalies using all registered detectors.
func (se *SecurityEngine) Analyze(ctx context.Context, device domain.Device) {
	// Run all detectors
	var allAlerts []domain.Alert
	for _, detector := range se.detectors {
		alerts := detector.Analyze(&device, se.Registry)
		allAlerts = append(allAlerts, alerts...)
	}

	// Add all alerts at once with a single lock
	se.mu.Lock()
	se.alerts = append(se.alerts, allAlerts...)
	se.mu.Unlock()
}

// AnalyzeNetwork is a placeholder for network-wide analysis.
func (se *SecurityEngine) AnalyzeNetwork() []domain.Alert {
	return se.GetAlerts(context.Background())
}
