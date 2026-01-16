package ports

import "github.com/lcalzada-xor/wmap/internal/core/domain"

// DeauthService defines the interface for deauthentication attacks.
type DeauthService interface {
	// StartAttack initiates a new deauth attack
	StartAttack(config domain.DeauthAttackConfig) (string, error)
	// StopAttack stops a running attack. Force stops it immediately without graceful cleanup if needed.
	StopAttack(id string, force bool) error
	// GetAttackStatus returns the current status of an attack
	GetAttackStatus(id string) (domain.DeauthAttackStatus, error)
	ListActiveAttacks() []domain.DeauthAttackStatus
	SetLogger(logger func(string, string))
	StopAll()
}
