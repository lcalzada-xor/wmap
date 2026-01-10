package middleware

import (
	"net/http"
	"strings"
)

// AuthRedirectMiddleware redirects unauthenticated users to login page
// for protected static pages
func AuthRedirectMiddleware(authService interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow public paths
			publicPaths := []string{
				"/login.html",
				"/js/",
				"/css/",
				"/style.css",
				"/fonts/",
				"/images/",
				"/favicon.ico",
			}

			// Check if path is public
			for _, path := range publicPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// For root or index.html, check authentication
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				// Check for session cookie
				cookie, err := r.Cookie("session_token")
				if err != nil || cookie.Value == "" {
					// No session, redirect to login
					http.Redirect(w, r, "/login.html", http.StatusSeeOther)
					return
				}
			}

			// Serve the file
			next.ServeHTTP(w, r)
		})
	}
}
