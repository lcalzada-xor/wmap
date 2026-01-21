package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DeauthService defines the operational interface for deauthentication-based attacks.
type DeauthService interface {
	// StartAttack initiates a new deauth task.
	StartAttack(ctx context.Context, config domain.DeauthAttackConfig) (id string, err error)

	// StopAttack terminates a specific running attack.
	StopAttack(ctx context.Context, id string, force bool) error

	// GetAttackStatus retrieves telemetry for a single attack.
	GetAttackStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error)

	// ListActiveAttacks returns all currently running deauth tasks.
	ListActiveAttacks(ctx context.Context) []domain.DeauthAttackStatus

	// SetLogger attaches a telemetry output for attack progress.
	SetLogger(logger func(mac, message string))

	// StopAll performs a global shutdown of all active deauth tasks.
	StopAll(ctx context.Context)
}
