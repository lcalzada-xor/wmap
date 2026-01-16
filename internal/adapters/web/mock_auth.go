package web

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// MockAuthService is a mock of ports.AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(ctx context.Context, creds domain.Credentials) (string, error) {
	args := m.Called(ctx, creds)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) ValidateToken(ctx context.Context, token string) (*domain.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthService) CreateUser(ctx context.Context, user domain.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}
