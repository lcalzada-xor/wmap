package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// AuthService coordinates credentials validation and session management.
type AuthService interface {
	// Login performs credential validation and returns a secure session token.
	Login(ctx context.Context, creds domain.Credentials) (token string, err error)

	// ValidateToken verifies the authenticity and expiration of a session token.
	ValidateToken(ctx context.Context, token string) (*domain.User, error)

	// Logout invalidates the provided session token.
	Logout(ctx context.Context, token string) error

	// CreateUser provision a new user in the system. Typically restricted to admin roles.
	CreateUser(ctx context.Context, user domain.User, password string) error
}

// UserRepository provides access to stored user profiles.
type UserRepository interface {
	// Save persists a user's information.
	Save(ctx context.Context, user domain.User) error

	// GetByUsername retrieves a user by their unique identifier.
	GetByUsername(ctx context.Context, username string) (*domain.User, error)

	// GetByID retrieves a user by their internal UUID.
	GetByID(ctx context.Context, id string) (*domain.User, error)

	// List returns all registered users.
	List(ctx context.Context) ([]domain.User, error)
}
