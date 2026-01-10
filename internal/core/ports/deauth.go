package ports

import "github.com/lcalzada-xor/wmap/internal/core/domain"

// DeauthService defines the interface for deauthentication attacks.
type DeauthService interface {
	StartAttack(config domain.DeauthAttackConfig) (string, error)
	StopAttack(id string) error
	GetAttackStatus(id string) (domain.DeauthAttackStatus, error)
	ListActiveAttacks() []domain.DeauthAttackStatus
	SetLogger(logger func(string, string))
}
