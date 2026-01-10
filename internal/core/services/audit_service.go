package services

import (
	"context"
	"time"

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

func (s *AuditService) Log(ctx context.Context, action, target, details string) error {
	// Extract User from Context (requires convention)
	// We'll assume the controller puts "audit_user" or similar in context,
	// or we just pass it explicitly. For now, let's look for "user" from our auth middleware
	// but context keys are tricky across packages.

	// Implementation note: The controller calls this. The controller has the User object.
	// It's cleaner if the controller passes user info.
	// Check if context has value. We can't import middleware here (cycle).
	// We'll define a simpler pattern: Controller passes user, or we extract from a common domain key.

	userID := "system"
	username := "system"

	// Attempt to get user from context if available via string key (simple but fragile)
	// or assume the caller handles context injection using a shared key in domain?
	// For this iteration, let's try to grab it if we can, or rely on caller to populate context.
	// Let's assume we use a domain-defined context key.

	// To avoid circular deps with middleware, we won't import middleware.

	entry := domain.AuditLog{
		UserID:    userID,
		Username:  username,
		Action:    action,
		Target:    target,
		Details:   details,
		Timestamp: time.Now(),
	}

	// Try to extract user from context if we set it up properly in domain
	if u, ok := ctx.Value("audit_user").(domain.User); ok {
		entry.UserID = u.ID
		entry.Username = u.Username
	} else if uPtr, ok := ctx.Value("audit_user").(*domain.User); ok {
		entry.UserID = uPtr.ID
		entry.Username = uPtr.Username
	}

	return s.repo.SaveAuditLog(entry)
}

func (s *AuditService) GetLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	return s.repo.ListAuditLogs(limit)
}
