package services

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
)

type Session struct {
	UserID    string
	Role      domain.Role
	ExpiresAt time.Time
}

type AuthService struct {
	repo          ports.UserRepository
	sessions      map[string]Session
	loginAttempts map[string]int
	mu            sync.RWMutex
	sessionTTL    time.Duration
}

func NewAuthService(repo ports.UserRepository) *AuthService {
	return &AuthService{
		repo:          repo,
		sessions:      make(map[string]Session),
		loginAttempts: make(map[string]int),
		sessionTTL:    24 * time.Hour,
	}
}

func (s *AuthService) Login(ctx context.Context, creds domain.Credentials) (string, error) {
	// Simple Rate Limiting (Reset periodically in a real app)
	s.mu.Lock()
	if s.loginAttempts[creds.Username] > 5 {
		s.mu.Unlock()
		return "", ErrRateLimitExceeded
	}
	s.mu.Unlock()

	user, err := s.repo.GetByUsername(creds.Username)
	if err != nil {
		s.mu.Lock()
		s.loginAttempts[creds.Username]++
		s.mu.Unlock()
		return "", ErrInvalidCredentials // Generic error to avoid enumeration
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password)); err != nil {
		s.mu.Lock()
		s.loginAttempts[creds.Username]++
		s.mu.Unlock()
		return "", ErrInvalidCredentials
	}

	// Reset attempts on success
	s.mu.Lock()
	delete(s.loginAttempts, creds.Username)
	s.mu.Unlock()

	// Create Session
	token := uuid.New().String()
	s.mu.Lock()
	s.sessions[token] = Session{
		UserID:    user.ID,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(s.sessionTTL),
	}
	s.mu.Unlock()

	return token, nil
}

func (s *AuthService) ValidateToken(ctx context.Context, token string) (*domain.User, error) {
	s.mu.RLock()
	session, ok := s.sessions[token]
	s.mu.RUnlock()

	if !ok {
		return nil, errors.New("invalid session")
	}

	if time.Now().After(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
		return nil, ErrTokenExpired
	}

	return s.repo.GetByID(session.UserID)
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	return nil
}

func (s *AuthService) CreateUser(ctx context.Context, user domain.User, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	user.PasswordHash = string(hash)
	user.CreatedAt = time.Now()

	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	return s.repo.Save(user)
}
