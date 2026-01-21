package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenExpired       = errors.New("token expired")
	ErrRateLimitExceeded  = errors.New("rate limit exceeded")
	ErrInvalidSession     = errors.New("invalid session")
)

// Session represents an active user session.
type Session struct {
	UserID    string
	Role      domain.Role
	ExpiresAt time.Time
}

// AuthService implements ports.AuthService.
// It coordinates credentials validation and session management.
type AuthService struct {
	repo          ports.UserRepository
	sessions      map[string]Session
	loginAttempts map[string]int
	mu            sync.RWMutex
	sessionTTL    time.Duration
}

// NewAuthService creates a new authentication service instance.
func NewAuthService(repo ports.UserRepository) *AuthService {
	return &AuthService{
		repo:          repo,
		sessions:      make(map[string]Session),
		loginAttempts: make(map[string]int),
		sessionTTL:    24 * time.Hour,
	}
}

// Login validates user credentials and returns a session token.
func (s *AuthService) Login(ctx context.Context, creds domain.Credentials) (string, error) {
	if err := s.checkRateLimit(creds.Username); err != nil {
		return "", err
	}

	user, err := s.repo.GetByUsername(ctx, creds.Username)
	if err != nil {
		s.incrementAttempts(creds.Username)
		return "", ErrInvalidCredentials // Generic error to avoid enumeration
	}

	if err := s.verifyPassword(user.PasswordHash, creds.Password); err != nil {
		s.incrementAttempts(creds.Username)
		return "", ErrInvalidCredentials
	}

	s.resetAttempts(creds.Username)

	return s.createSession(user)
}

// ValidateToken verifies a session token and returns the associated user.
func (s *AuthService) ValidateToken(ctx context.Context, token string) (*domain.User, error) {
	s.mu.RLock()
	session, ok := s.sessions[token]
	s.mu.RUnlock()

	if !ok {
		return nil, ErrInvalidSession
	}

	if time.Now().After(session.ExpiresAt) {
		s.Logout(ctx, token)
		return nil, ErrTokenExpired
	}

	user, err := s.repo.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}

	return user, nil
}

// Logout invalidates a session token.
func (s *AuthService) Logout(ctx context.Context, token string) error {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	return nil
}

// CreateUser provision a new user with a hashed password.
func (s *AuthService) CreateUser(ctx context.Context, user domain.User, password string) error {
	hash, err := s.hashPassword(password)
	if err != nil {
		return err
	}

	user.PasswordHash = hash
	user.CreatedAt = time.Now()

	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	return s.repo.Save(ctx, user)
}

// Private helpers

func (s *AuthService) checkRateLimit(username string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loginAttempts[username] >= 5 {
		return ErrRateLimitExceeded
	}
	return nil
}

func (s *AuthService) incrementAttempts(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginAttempts[username]++
}

func (s *AuthService) resetAttempts(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.loginAttempts, username)
}

func (s *AuthService) verifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

func (s *AuthService) createSession(user *domain.User) (string, error) {
	token := uuid.New().String()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[token] = Session{
		UserID:    user.ID,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(s.sessionTTL),
	}

	return token, nil
}
