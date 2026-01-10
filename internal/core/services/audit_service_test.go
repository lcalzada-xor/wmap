package services

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

func (m *MockAuditRepository) SaveAuditLog(log domain.AuditLog) error {
	args := m.Called(log)
	return args.Error(0)
}

func (m *MockAuditRepository) ListAuditLogs(limit int) ([]domain.AuditLog, error) {
	args := m.Called(limit)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

func TestAuditService_Log(t *testing.T) {
	mockRepo := new(MockAuditRepository)
	svc := NewAuditService(mockRepo)

	ctx := context.Background()

	// Test basic logging
	mockRepo.On("SaveAuditLog", mock.MatchedBy(func(l domain.AuditLog) bool {
		return l.Action == "TEST_ACTION" && l.Target == "target" && l.UserID == "system"
	})).Return(nil)

	err := svc.Log(ctx, "TEST_ACTION", "target", "details")
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

func TestAuditService_LogWithUser(t *testing.T) {
	mockRepo := new(MockAuditRepository)
	svc := NewAuditService(mockRepo)

	// Inject user into context (assuming we use a string key properly? implementation used "audit_user")
	user := domain.User{ID: "u-123", Username: "operator"}
	ctx := context.WithValue(context.Background(), "audit_user", user)

	mockRepo.On("SaveAuditLog", mock.MatchedBy(func(l domain.AuditLog) bool {
		return l.Action == "TEST" && l.Username == "operator" && l.UserID == "u-123"
	})).Return(nil)

	err := svc.Log(ctx, "TEST", "t", "d")
	assert.NoError(t, err)
}

func TestAuditService_GetLogs(t *testing.T) {
	mockRepo := new(MockAuditRepository)
	svc := NewAuditService(mockRepo)

	logs := []domain.AuditLog{{ID: 1, Action: "LOGIN"}}
	mockRepo.On("ListAuditLogs", 10).Return(logs, nil)

	res, err := svc.GetLogs(context.Background(), 10)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "LOGIN", res[0].Action)
}
