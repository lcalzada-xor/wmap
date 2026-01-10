package services

import (
	"context"
	"errors"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// MockUserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Save(user domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByUsername(username string) (*domain.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(id string) (*domain.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) List() ([]domain.User, error) {
	args := m.Called()
	return args.Get(0).([]domain.User), args.Error(1)
}

func TestAuthService_Login(t *testing.T) {
	mockRepo := new(MockUserRepository)
	svc := NewAuthService(mockRepo)

	// Reduce rate limit window logic for testing?
	// The service uses internal maps, we can just test normal flow.

	password := "secret123"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "u-1",
		Username:     "admin",
		PasswordHash: string(hashed),
		Role:         domain.RoleAdmin,
	}

	// 1. Success
	mockRepo.On("GetByUsername", "admin").Return(user, nil)
	// Expect Save to be called for LastLogin update
	mockRepo.On("Save", mock.MatchedBy(func(u domain.User) bool {
		return u.ID == "u-1"
	})).Return(nil)

	token, err := svc.Login(context.Background(), domain.Credentials{Username: "admin", Password: "secret123"})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// 2. Wrong Password
	mockRepo.On("GetByUsername", "admin_fail").Return(user, nil)
	token, err = svc.Login(context.Background(), domain.Credentials{Username: "admin_fail", Password: "wrong"})
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Equal(t, "invalid credentials", err.Error())

	// 3. User Not Found
	mockRepo.On("GetByUsername", "ghost").Return(nil, errors.New("not found"))
	token, err = svc.Login(context.Background(), domain.Credentials{Username: "ghost", Password: "any"})
	assert.Error(t, err)
	assert.Equal(t, "invalid credentials", err.Error()) // Should mask not found
}

func TestAuthService_ValidateToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	svc := NewAuthService(mockRepo)

	// Need to successfully login first to get a token (since sessions are in-memory private map)
	// We can't inject sessions directly unless we export them or use interface.
	// We will simulate a login first.

	password := "pass"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	user := &domain.User{ID: "u-1", Username: "user", PasswordHash: string(hashed)}

	mockRepo.On("GetByUsername", "user").Return(user, nil)
	mockRepo.On("Save", mock.Anything).Return(nil)

	token, _ := svc.Login(context.Background(), domain.Credentials{Username: "user", Password: "pass"})

	// Expect GetByID to be called during Validation
	mockRepo.On("GetByID", "u-1").Return(user, nil)

	// Test Validate
	u, err := svc.ValidateToken(context.Background(), token)
	assert.NoError(t, err)
	assert.Equal(t, "user", u.Username)

	// Test Invalid Token
	u, err = svc.ValidateToken(context.Background(), "fake-token")
	assert.Error(t, err)
	assert.Nil(t, u)
}

func TestAuthService_CreateUser(t *testing.T) {
	mockRepo := new(MockUserRepository)
	svc := NewAuthService(mockRepo)

	newUser := domain.User{Username: "newuser", Role: domain.RoleViewer}

	// Mock Save - verify hashing happens (we can't verify exact hash but can check length)
	mockRepo.On("Save", mock.MatchedBy(func(u domain.User) bool {
		return u.Username == "newuser" && len(u.PasswordHash) > 0 && u.ID != ""
	})).Return(nil)

	err := svc.CreateUser(context.Background(), newUser, "password")
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}
