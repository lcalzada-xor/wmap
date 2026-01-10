package storage

import (
	"errors"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"gorm.io/gorm"
)

// Ensure interface compliance
var _ ports.UserRepository = (*SQLiteAdapter)(nil)

// Save creates or updates a user.
func (a *SQLiteAdapter) Save(user domain.User) error {
	return a.db.Save(&user).Error
}

// GetByUsername retrieves a user by their username.
func (a *SQLiteAdapter) GetByUsername(username string) (*domain.User, error) {
	var user domain.User
	if err := a.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByID retrieves a user by their ID.
func (a *SQLiteAdapter) GetByID(id string) (*domain.User, error) {
	var user domain.User
	if err := a.db.First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// List returns all users.
func (a *SQLiteAdapter) List() ([]domain.User, error) {
	var users []domain.User
	if err := a.db.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
