package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/web/middleware"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// MockAuthService helper for tests
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(ctx context.Context, creds domain.Credentials) (string, error) {
	args := m.Called(ctx, creds)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) ValidateToken(ctx context.Context, token string) (*domain.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthService) CreateUser(ctx context.Context, user domain.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}

func TestAuthMiddleware_CookieFix(t *testing.T) {
	mockAuth := &MockAuthService{}
	mw := middleware.AuthMiddleware(mockAuth)

	// Protected handler that checks if user is in context
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(middleware.UserContextKey).(*domain.User)
		if !ok || user == nil {
			http.Error(w, "Context missing user", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User: " + user.Username))
	})

	t.Run("Accepts auth_token cookie and calls ValidateToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "valid-token-123"})
		w := httptest.NewRecorder()

		// Mock Expectation
		expectedUser := &domain.User{ID: "1", Username: "admin", Role: domain.RoleAdmin}
		mockAuth.On("ValidateToken", mock.Anything, "valid-token-123").Return(expectedUser, nil).Once()

		handler := mw(protectedHandler)
		handler.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Result().StatusCode)
		}
		if w.Body.String() != "User: admin" {
			t.Errorf("Expected 'User: admin', got '%s'", w.Body.String())
		}
		mockAuth.AssertExpectations(t)
	})

	t.Run("Rejects missing auth_token (fails session_token check)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "ignored"})
		w := httptest.NewRecorder()

		// No Expectation on ValidateToken because middleware shouldn't find the token
		// unless it erroneously checks session_token

		handler := mw(protectedHandler)
		handler.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Result().StatusCode)
		}
	})
}
