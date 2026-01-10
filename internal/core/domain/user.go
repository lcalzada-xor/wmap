package domain

import (
	"time"
)

// Role defines the authorization level of a user.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// User represents an authenticated user in the system.
type User struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	Username     string    `json:"username" gorm:"uniqueIndex"`
	PasswordHash string    `json:"-"` // Never expose hash in JSON
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// Credentials represents the login request body.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
