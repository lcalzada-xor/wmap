package web

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/web"
)

func SetupRoutes(s *Server) http.Handler {
	mux := http.NewServeMux()

	// WebSocket endpoint
	wsHandler := s.WSManager.HandleWebSocket
	if s.MockWSHandler != nil {
		wsHandler = s.MockWSHandler
	}
	mux.HandleFunc("GET /ws", wsHandler)

	// Core API
	mux.HandleFunc("POST /api/scan", s.API.HandleScan)
	mux.HandleFunc("GET /api/config", s.API.HandleGetConfig)
	mux.HandleFunc("POST /api/config/persistence", s.API.HandleTogglePersistence)
	mux.HandleFunc("GET /api/stats", s.API.HandleGetStats)
	mux.HandleFunc("GET /api/channels", s.API.HandleGetChannels)
	mux.HandleFunc("POST /api/channels", s.API.HandleUpdateChannels)
	mux.HandleFunc("GET /api/interfaces", s.API.HandleListInterfaces)

	// Serve static files from embedded FS
	staticFS, err := fs.Sub(webassets.DistFS, "dist")
	if err != nil {
		panic(err) // This should never happen if build is correct
	}
	fileServer := http.FileServer(http.FS(staticFS))

	// Catch-all handler for SPA
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If the path has a file extension, it's likely a static asset
		if strings.Contains(r.URL.Path, ".") {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Otherwise, serve index.html for SPA routing
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})

	// Apply Rate Limiting Middleware
	limiter := NewRateLimiter(100, 1*time.Minute)
	return RateLimitMiddleware(limiter)(mux)
}
