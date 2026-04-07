package web

import (
	"net/http"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/web/middleware"
)

func SetupRoutes(s *Server) http.Handler {
	mux := http.NewServeMux()

	// WebSocket endpoint
	mux.HandleFunc("GET /ws", s.WSManager.HandleWebSocket)

	// Core API
	mux.HandleFunc("POST /api/scan", s.API.HandleScan)
	mux.HandleFunc("GET /api/config", s.API.HandleGetConfig)
	mux.HandleFunc("POST /api/config/persistence", s.API.HandleTogglePersistence)
	mux.HandleFunc("GET /api/stats", s.API.HandleGetStats)
	mux.HandleFunc("GET /api/channels", s.API.HandleGetChannels)
	mux.HandleFunc("POST /api/channels", s.API.HandleUpdateChannels)
	mux.HandleFunc("GET /api/interfaces", s.API.HandleListInterfaces)

	// Apply Rate Limiting Middleware
	limiter := middleware.NewRateLimiter(100, 1*time.Minute)
	return middleware.RateLimitMiddleware(limiter)(mux)
}
