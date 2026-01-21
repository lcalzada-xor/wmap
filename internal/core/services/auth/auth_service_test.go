package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// MockUserRepository implements ports.UserRepository for testing.
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Save(ctx context.Context, user domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) List(ctx context.Context) ([]domain.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.User), args.Error(1)
}

func TestAuthService_Login(t *testing.T) {
	mockRepo := new(MockUserRepository)
	svc := NewAuthService(mockRepo)
	ctx := context.Background()

	password := "secret123"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "u-1",
		Username:     "admin",
		PasswordHash: string(hashed),
		Role:         domain.RoleAdmin,
	}

	// 1. Success
	mockRepo.On("GetByUsername", ctx, "admin").Return(user, nil)

	token, err := svc.Login(ctx, domain.Credentials{Username: "admin", Password: "secret123"})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// 2. Wrong Password
	mockRepo.On("GetByUsername", ctx, "admin_fail").Return(user, nil)
	token, err = svc.Login(ctx, domain.Credentials{Username: "admin_fail", Password: "wrong"})
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Equal(t, ErrInvalidCredentials, err)

	// 3. User Not Found
	mockRepo.On("GetByUsername", ctx, "ghost").Return(nil, errors.New("not found"))
	token, err = svc.Login(ctx, domain.Credentials{Username: "ghost", Password: "any"})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err) // Should mask not found
}

func TestAuthService_ValidateToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	svc := NewAuthService(mockRepo)
	ctx := context.Background()

	password := "pass"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	user := &domain.User{ID: "u-1", Username: "user", PasswordHash: string(hashed)}

	mockRepo.On("GetByUsername", ctx, "user").Return(user, nil)

	token, _ := svc.Login(ctx, domain.Credentials{Username: "user", Password: "pass"})

	// Expect GetByID to be called during Validation
	mockRepo.On("GetByID", ctx, "u-1").Return(user, nil)

	// Test Validate
	u, err := svc.ValidateToken(ctx, token)
	assert.NoError(t, err)
	assert.Equal(t, "user", u.Username)

	// Test Invalid Token
	u, err = svc.ValidateToken(ctx, "fake-token")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestAuthService_CreateUser(t *testing.T) {
	mockRepo := new(MockUserRepository)
	svc := NewAuthService(mockRepo)
	ctx := context.Background()

	newUser := domain.User{Username: "newuser", Role: domain.RoleViewer}

	// Mock Save - verify hashing happens (we can't verify exact hash but can check length)
	mockRepo.On("Save", ctx, mock.MatchedBy(func(u domain.User) bool {
		return u.Username == "newuser" && len(u.PasswordHash) > 0 && u.ID != ""
	})).Return(nil)

	err := svc.CreateUser(ctx, newUser, "password")
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}
