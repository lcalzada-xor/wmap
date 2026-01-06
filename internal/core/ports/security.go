package ports

import "github.com/lcalzada-xor/wmap/internal/core/domain"

// SecurityEngine analyzes device behavior and attributes to detect anomalies.
type SecurityEngine interface {
	// Analyze performs security checks on a device and triggers alerts if necessary.
	Analyze(device domain.Device)

	// AddRule adds a dynamic alert rule.
	AddRule(rule domain.AlertRule)

	// GetAlerts returns the history of triggered alerts.
	GetAlerts() []domain.Alert
}
