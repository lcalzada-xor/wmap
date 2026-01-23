package server

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
	mux.Handle("/api/login", middleware.RateLimitMiddleware(loginLimiter)(http.HandlerFunc(s.AuthHandler.HandleLogin)))
	mux.HandleFunc("/api/logout", s.AuthHandler.HandleLogout)

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

	mux.Handle("/api/me", protect(s.AuthHandler.HandleMe))
	mux.Handle("/api/scan", protect(s.ScanHandler.HandleScan))
	mux.Handle("/api/export", protect(s.ExportHandler.HandleExport))
	mux.Handle("/api/config", protect(s.ConfigHandler.HandleGetConfig))
	mux.Handle("/api/config/persistence", protect(s.ConfigHandler.HandleTogglePersistence))
	mux.Handle("/api/stats", protect(s.ScanHandler.HandleGetStats))

	// Reports (Restricted to Operator/Admin)
	mux.Handle("/api/reports/download", protectOp(s.ReportHandler.HandleGenerateReport))

	// Audit Logs
	mux.Handle("/api/audit-logs", protect(s.AuditHandler.HandleGetLogs))

	// Workspace API
	mux.Handle("/api/workspaces/clear", protect(s.WorkspaceHandler.HandleClear))
	mux.Handle("/api/workspaces", protect(s.WorkspaceHandler.HandleListWorkspaces))
	mux.Handle("/api/workspaces/new", protect(s.WorkspaceHandler.HandleCreateWorkspace))
	mux.Handle("/api/workspaces/load", protect(s.WorkspaceHandler.HandleLoadWorkspace))
	mux.Handle("/api/workspace/status", protect(s.WorkspaceHandler.HandleStatus))
	mux.Handle("/api/workspaces/delete", protect(s.WorkspaceHandler.HandleDeleteWorkspace))

	mux.Handle("/api/channels", protect(s.ScanHandler.HandleChannels))
	mux.Handle("/api/interfaces", protect(s.ScanHandler.HandleListInterfaces))

	// Deauth Attack endpoints
	mux.Handle("/api/deauth/start", middleware.RateLimitMiddleware(deauthLimiter)(protectOp(s.DeauthHandler.HandleStart)))
	mux.Handle("/api/deauth/stop", middleware.RateLimitMiddleware(deauthLimiter)(protectOp(s.DeauthHandler.HandleStop)))
	mux.Handle("/api/deauth/status", protect(s.DeauthHandler.HandleStatus))
	mux.Handle("/api/deauth/list", protect(s.DeauthHandler.HandleList))

	// WPS Attack Endpoints
	mux.Handle("/api/wps/start", protectOp(s.WPSHandler.HandleStart))
	mux.Handle("/api/wps/stop/{id}", protectOp(s.WPSHandler.HandleStop))
	mux.Handle("/api/wps/status/{id}", protect(s.WPSHandler.HandleStatus))

	// Metrics endpoint (protected - requires authentication)
	mux.Handle("/metrics", protect(func(w http.ResponseWriter, r *http.Request) {
		promhttp.Handler().ServeHTTP(w, r)
	}))

	// Auth Flood Attack (New)
	mux.Handle("/api/attack/auth-flood/start", protectOp(s.AuthFloodHandler.HandleStart))
	mux.Handle("/api/attack/auth-flood/stop", protectOp(s.AuthFloodHandler.HandleStop))
	mux.Handle("/api/attack/auth-flood/status", protect(s.AuthFloodHandler.HandleStatus))

	// Vulnerability Management API
	mux.Handle("GET /api/vulnerabilities", protect(http.HandlerFunc(s.VulnHandler.GetVulnerabilities)))
	mux.Handle("GET /api/vulnerabilities/stats", protect(http.HandlerFunc(s.VulnHandler.GetVulnerabilityStats)))
	mux.Handle("GET /api/vulnerabilities/{id}", protect(http.HandlerFunc(s.VulnHandler.GetVulnerability)))
	mux.Handle("PUT /api/vulnerabilities/{id}/status", protect(http.HandlerFunc(s.VulnHandler.UpdateStatus)))

	// Reporting API (Phase 2)
	mux.Handle("POST /api/reports/executive", protect(http.HandlerFunc(s.ReportHandler.HandleGenerateExecutiveSummary)))

	// Capture/Handshake Management
	mux.Handle("/api/captures/open-folder", protect(http.HandlerFunc(s.CaptureHandler.HandleOpenHandshakeFolder)))

	return mux
}
