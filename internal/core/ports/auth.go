package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// AuthService defines the business logic for authentication.
type AuthService interface {
	// Login validates credentials and returns a session token.
	Login(ctx context.Context, creds domain.Credentials) (string, error)
	// ValidateToken checks if a token is valid and returns the associated user.
	ValidateToken(ctx context.Context, token string) (*domain.User, error)
	// Logout invalidates a session token.
	Logout(ctx context.Context, token string) error
	// CreateUser registers a new user (admin only).
	CreateUser(ctx context.Context, user domain.User, password string) error
}

// UserRepository defines the persistence layer for users.
type UserRepository interface {
	// Save creates or updates a user.
	Save(user domain.User) error
	// GetByUsername retrieves a user by their username.
	GetByUsername(username string) (*domain.User, error)
	// GetByID retrieves a user by their ID.
	GetByID(id string) (*domain.User, error)
	// List returns all users.
	List() ([]domain.User, error)
}
