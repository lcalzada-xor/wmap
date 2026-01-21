package audit

import (
	"context"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuditRepository
type MockAuditRepository struct {
	mock.Mock
}

func (m *MockAuditRepository) SaveAuditLog(ctx context.Context, log domain.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockAuditRepository) ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

func TestAuditService_Log(t *testing.T) {
	mockRepo := new(MockAuditRepository)
	svc := NewAuditService(mockRepo)

	ctx := context.Background()

	// Test basic logging
	mockRepo.On("SaveAuditLog", mock.Anything, mock.MatchedBy(func(l domain.AuditLog) bool {
		return l.Action == domain.ActionInfo && l.Target == "target" && l.UserID == "system"
	})).Return(nil)

	err := svc.Log(ctx, domain.ActionInfo, "target", "details")
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

func TestAuditService_LogWithUser(t *testing.T) {
	mockRepo := new(MockAuditRepository)
	svc := NewAuditService(mockRepo)

	// Inject user into context (assuming we use a string key properly? implementation used "audit_user")
	user := domain.User{ID: "u-123", Username: "operator"}
	ctx := context.WithValue(context.Background(), "audit_user", user)

	mockRepo.On("SaveAuditLog", mock.Anything, mock.MatchedBy(func(l domain.AuditLog) bool {
		return l.Action == domain.ActionLogin && l.Username == "operator" && l.UserID == "u-123"
	})).Return(nil)

	err := svc.Log(ctx, domain.ActionLogin, "t", "d")
	assert.NoError(t, err)
}

func TestAuditService_GetLogs(t *testing.T) {
	mockRepo := new(MockAuditRepository)
	svc := NewAuditService(mockRepo)

	logs := []domain.AuditLog{{ID: 1, Action: domain.ActionLogin}}
	mockRepo.On("ListAuditLogs", mock.Anything, 10).Return(logs, nil)

	res, err := svc.GetLogs(context.Background(), 10)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, domain.ActionLogin, res[0].Action)
}
