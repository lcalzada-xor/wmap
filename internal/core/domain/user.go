package domain

import (
	"errors"
	"time"
)

// Role defines the authorization level of a user.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

var (
	ErrInvalidRole     = errors.New("invalid user role")
	ErrEmptyUsername   = errors.New("username cannot be empty")
	ErrInvalidPassword = errors.New("password does not meet security requirements")
)

// IsValid checks if the role is a recognized system role.
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// User represents an authenticated user in the system.
// This is a pure domain entity, decoupled from infrastructure (DB tags).
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // Never expose hash in JSON
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// NewUser creates a new validated user instance.
func NewUser(id, username string, role Role) (*User, error) {
	if username == "" {
		return nil, ErrEmptyUsername
	}
	if !role.IsValid() {
		return nil, ErrInvalidRole
	}

	return &User{
		ID:        id,
		Username:  username,
		Role:      role,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// IsAdmin returns true if the user has administrative privileges.
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// UpdateLastLogin refreshes the last login timestamp.
func (u *User) UpdateLastLogin() {
	u.LastLogin = time.Now().UTC()
}

// Validate ensures the user entity is in a valid state.
func (u *User) Validate() error {
	if u.Username == "" {
		return ErrEmptyUsername
	}
	if !u.Role.IsValid() {
		return ErrInvalidRole
	}
	return nil
}

// --- DTOs / Request Objects ---

// Credentials represents the login request body.
// Note: This belongs to the application/transport layer but is kept here for
// public API compatibility within the core module.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
