package ports

import "github.com/lcalzada-xor/wmap/internal/core/domain"

// WPSAttackService defines the interface for executing WPS attacks
type WPSAttackService interface {
	// StartAttack initiates a new Pixie Dust attack
	StartAttack(config domain.WPSAttackConfig) (string, error)
	// StopAttack stops an active attack. Force stops it immediately.
	StopAttack(id string, force bool) error
	// GetStatus returns the status of an attack
	GetStatus(id string) (domain.WPSAttackStatus, error)
	StopAll()
	// HealthCheck verifies if the necessary tools (reaver, pixiewps) are installed
	HealthCheck() error
}
