package ports

import "github.com/lcalzada-xor/wmap/internal/core/domain"

// WPSAttackService defines the interface for executing WPS attacks
type WPSAttackService interface {
	// StartAttack initiates a new Pixie Dust attack
	StartAttack(config domain.WPSAttackConfig) (string, error)

	// StopAttack forces a stop of the attack with the given ID
	StopAttack(id string) error

	// GetStatus returns the current status of the attack
	GetStatus(id string) (domain.WPSAttackStatus, error)
}
