package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// WPSAttackService defines the operational interface for WPS-related vulnerability testing.
type WPSAttackService interface {
	// StartAttack initiates a targeted WPS attack (e.g., Pixie Dust).
	StartAttack(ctx context.Context, config domain.WPSAttackConfig) (id string, err error)

	// StopAttack terminates a specific running WPS task.
	StopAttack(ctx context.Context, id string, force bool) error

	// GetStatus retrieves the current progress/result of an attack.
	GetStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error)

	// StopAll ensures a clean state by stopping all ongoing WPS assessments.
	StopAll(ctx context.Context)

	// HealthCheck verifies the presence and compatibility of required external tools (e.g., reaver).
	HealthCheck(ctx context.Context) error
}
