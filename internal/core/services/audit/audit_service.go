package audit

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	// We might need to access middleware context key for User ID
	// But services usually shouldn't depend on web middleware.
	// Best pattern: Pass user info in Context from controller.
)

type AuditService struct {
	repo ports.AuditRepository
}

func NewAuditService(repo ports.AuditRepository) *AuditService {
	return &AuditService{repo: repo}
}

func (s *AuditService) Log(ctx context.Context, action domain.AuditAction, target, details string) error {
	// Extract User from Context
	userID := "system"
	username := "system"

	// Try to extract user from context if we set it up properly in domain
	if u, ok := ctx.Value("audit_user").(domain.User); ok {
		userID = u.ID
		username = u.Username
	} else if uPtr, ok := ctx.Value("audit_user").(*domain.User); ok {
		userID = uPtr.ID
		username = uPtr.Username
	}

	// Use Domain Factory to ensure business rules
	entry, err := domain.NewAuditLog(userID, username, action, target, details, "") // IP extraction could be added here
	if err != nil {
		return err
	}

	return s.repo.SaveAuditLog(ctx, *entry)
}

func (s *AuditService) GetLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	return s.repo.ListAuditLogs(ctx, limit)
}
