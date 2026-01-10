package web

import (
	"net/http"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/web/middleware"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func SetupRoutes(s *Server) http.Handler {
	mux := http.NewServeMux()

	// Serve static files with auth redirect for index.html
	fileServer := http.FileServer(http.Dir("./internal/adapters/web/static"))
	mux.Handle("/", middleware.AuthRedirectMiddleware(s.AuthService)(fileServer))

	// Rate limiters
	loginLimiter := middleware.NewRateLimiter(5, 1*time.Minute)   // 5 login attempts per minute
	deauthLimiter := middleware.NewRateLimiter(10, 1*time.Minute) // 10 deauth requests per minute

	// Public API (with rate limiting)
	mux.Handle("/api/login", middleware.RateLimitMiddleware(loginLimiter)(http.HandlerFunc(s.handleLogin)))
	mux.HandleFunc("/api/logout", s.handleLogout)

	// Protected API
	auth := middleware.AuthMiddleware(s.AuthService)
	protect := func(h http.HandlerFunc) http.Handler {
		return auth(h)
	}

	// WebSocket endpoint (protected)
	// Now handled by WSManager via Server
	mux.Handle("/ws", protect(s.WSManager.HandleWebSocket))

	// RBAC Middleware Helper (Operator Level)
	requireOperator := middleware.RoleMiddleware(domain.RoleOperator)
	protectOp := func(h http.HandlerFunc) http.Handler {
		return auth(requireOperator(h))
	}

	mux.Handle("/api/me", protect(s.handleMe))
	mux.Handle("/api/scan", protect(s.handleScan))
	mux.Handle("/api/export", protect(s.handleExport))
	mux.Handle("/api/config", protect(s.handleGetConfig))
	mux.Handle("/api/config/persistence", protect(s.handleTogglePersistence))
	mux.Handle("/api/stats", protect(s.handleGetStats))

	// Reports (Restricted to Operator/Admin)
	mux.Handle("/api/reports/download", protectOp(s.handleGenerateReport))

	// Audit Logs
	mux.Handle("/api/audit-logs", protect(s.handleGetAuditLogs))

	// Workspace API
	mux.Handle("/api/workspaces/clear", protect(s.handleWorkspaceClear))
	mux.Handle("/api/workspaces", protect(s.handleListWorkspaces))
	mux.Handle("/api/workspaces/new", protect(s.handleCreateWorkspace))
	mux.Handle("/api/workspaces/load", protect(s.handleLoadWorkspace))
	mux.Handle("/api/workspace/status", protect(s.handleWorkspaceStatus))

	mux.Handle("/api/channels", protect(s.handleChannels))
	mux.Handle("/api/interfaces", protect(s.handleListInterfaces))

	// Deauth Attack endpoints
	mux.Handle("/api/deauth/start", middleware.RateLimitMiddleware(deauthLimiter)(protectOp(s.handleDeauthStart)))
	mux.Handle("/api/deauth/stop", middleware.RateLimitMiddleware(deauthLimiter)(protectOp(s.handleDeauthStop)))
	mux.Handle("/api/deauth/status", protect(s.handleDeauthStatus))
	mux.Handle("/api/deauth/list", protect(s.handleDeauthList))

	// WPS Attack Endpoints
	mux.Handle("/api/wps/start", protectOp(s.handleStartWPSAttack))
	mux.Handle("/api/wps/stop/{id}", protectOp(s.handleStopWPSAttack))
	mux.Handle("/api/wps/status/{id}", protect(s.handleGetWPSStatus))

	// Metrics endpoint (protected - requires authentication)
	mux.Handle("/metrics", protect(func(w http.ResponseWriter, r *http.Request) {
		promhttp.Handler().ServeHTTP(w, r)
	}))

	return mux
}
