package fingerprint

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure cases
var (
	// ErrInvalidMAC indicates the MAC address format is invalid
	ErrInvalidMAC = errors.New("invalid MAC address format")

	// ErrVendorNotFound indicates no vendor was found for the given MAC
	ErrVendorNotFound = errors.New("vendor not found")

	// ErrDatabaseUnavailable indicates the OUI database is not accessible
	ErrDatabaseUnavailable = errors.New("OUI database unavailable")

	// ErrEmptyMAC indicates an empty MAC address was provided
	ErrEmptyMAC = errors.New("empty MAC address")

	// ErrRepositoryClosed indicates the repository has been closed
	ErrRepositoryClosed = errors.New("repository is closed")
)

// DatabaseError wraps database-specific errors with context
type DatabaseError struct {
	Op  string // Operation that failed (e.g., "lookup", "insert")
	Err error  // Underlying error
}

func (e *DatabaseError) Error() string {
	return fmt.Sprintf("database %s failed: %v", e.Op, e.Err)
}

func (e *DatabaseError) Unwrap() error {
	return e.Err
}

// ValidationError wraps validation errors with the invalid value
type ValidationError struct {
	Field string // Field that failed validation
	Value string // Invalid value
	Err   error  // Underlying error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for %s=%q: %v", e.Field, e.Value, e.Err)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}
