package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/web/middleware"
)

func TestAuthRedirectMiddleware_Fixed(t *testing.T) {
	// Mock next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create middleware
	// We pass nil for authService as it is not used in the cookie check block we modified
	mw := middleware.AuthRedirectMiddleware(nil)
	handler := mw(nextHandler)

	t.Run("Redirects when no cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusSeeOther {
			t.Errorf("Expected status 303 SeeOther, got %d", w.Result().StatusCode)
		}
		loc, _ := w.Result().Location()
		if loc.Path != "/login.html" {
			t.Errorf("Expected redirect to /login.html, got %s", loc.Path)
		}
	})

	t.Run("Allows access with auth_token cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "valid-token"})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 OK, got %d", w.Result().StatusCode)
		}
		if w.Body.String() != "OK" {
			t.Errorf("Expected body OK, got %s", w.Body.String())
		}
	})

	t.Run("Redirects with wrong cookie name (regression check)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "valid-token"})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Should redirect because we changed the requirement to "auth_token"
		if w.Result().StatusCode != http.StatusSeeOther {
			t.Errorf("Expected status 303 SeeOther, got %d", w.Result().StatusCode)
		}
	})
}
