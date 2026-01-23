package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// SecurityEngine analyzes device behavior and attributes to detect security anomalies.
type SecurityEngine interface {
	// Analyze performs heuristic and rule-based checks on a device.
	Analyze(ctx context.Context, device domain.Device)

	// AddRule injects a new detection rule at runtime.
	AddRule(ctx context.Context, rule domain.AlertRule)

	// GetAlerts returns the history of detected security events.
	GetAlerts(ctx context.Context) []domain.Alert
}

// VulnerabilityNotifier handles the real-time dissemination of security findings.
type VulnerabilityNotifier interface {
	// NotifyNewVulnerability emits a notification for a newly discovered weakness.
	NotifyNewVulnerability(ctx context.Context, vuln domain.VulnerabilityRecord)

	// NotifyVulnerabilityConfirmed emits a notification when a vulnerability is confirmed via active validation.
	NotifyVulnerabilityConfirmed(ctx context.Context, vuln domain.VulnerabilityRecord)
}
