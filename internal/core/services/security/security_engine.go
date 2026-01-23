package security

import (
	"context"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

const MaxAlertsHistory = 1000

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
		&ClientKarmaDetector{},
		&APKarmaDetector{},
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
	// Add all alerts at once with a single lock
	se.mu.Lock()
	defer se.mu.Unlock()

	for _, alert := range allAlerts {
		// Basic deduplication: Check internal buffer for recent duplicate
		// Optimization: Only check last 50 alerts to avoid O(N^2) on large history
		isDuplicate := false
		checkLimit := len(se.alerts)
		if checkLimit > 50 {
			checkLimit = 50
		}

		for i := 0; i < checkLimit; i++ {
			// Check from end (most recent)
			existing := se.alerts[len(se.alerts)-1-i]
			if existing.Type == alert.Type &&
				existing.Subtype == alert.Subtype &&
				existing.DeviceMAC == alert.DeviceMAC &&
				existing.TargetMAC == alert.TargetMAC {
				// Duplicate found recently, skip
				isDuplicate = true
				break
			}
		}

		if !isDuplicate {
			se.alerts = append(se.alerts, alert)
		}
	}

	// Enforce capacity limit (Ring buffer style - drop oldest)
	if len(se.alerts) > MaxAlertsHistory {
		// Keep the most recent MaxAlertsHistory
		offset := len(se.alerts) - MaxAlertsHistory
		// Optimization: Re-slice to avoid allocating new array if possible,
		// but for long-running service, we might want to let GC reclaim old backing array eventually.
		// For now simple re-slice is fine.
		se.alerts = se.alerts[offset:]
	}
}

// AnalyzeNetwork is a placeholder for network-wide analysis.
func (se *SecurityEngine) AnalyzeNetwork() []domain.Alert {
	return se.GetAlerts(context.Background())
}
