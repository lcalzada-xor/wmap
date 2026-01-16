package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

type contextKey string

const UserContextKey contextKey = "user"

// AuthMiddleware ensures the request has a valid session.
func AuthMiddleware(authService ports.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip check for login/public endpoints
			// Ideally this is handled by router groups, but here we do simple path check if needed
			// or apply middleware selectively.

			// Get token from cookie
			cookie, err := r.Cookie("auth_token")
			var token string
			if err == nil {
				token = cookie.Value
			}

			// Fallback to Header (for API clients)
			if token == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					token = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if token == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Validate Token
			user, err := authService.ValidateToken(r.Context(), token)
			if err != nil {
				// Clear cookie if invalid
				http.SetCookie(w, &http.Cookie{
					Name:   "auth_token",
					Value:  "",
					Path:   "/",
					MaxAge: -1,
				})
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Add user to context
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RoleMiddleware checks if the user has the required role.
func RoleMiddleware(requiredRole domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(UserContextKey).(*domain.User)
			if !ok || user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Simple hierarchy: Admin > Operator > Viewer
			if !hasPermission(user.Role, requiredRole) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func hasPermission(userRole, requiredRole domain.Role) bool {
	if userRole == domain.RoleAdmin {
		return true
	}
	if userRole == domain.RoleOperator {
		return requiredRole != domain.RoleAdmin
	}
	if userRole == domain.RoleViewer {
		return requiredRole == domain.RoleViewer
	}
	return false
}
