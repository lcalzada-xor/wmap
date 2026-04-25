package web

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// Server handles HTTP and WebSocket connections.
type Server struct {
	Addr      string
	Service   ports.NetworkService
	WSManager *Manager

	API           *API
	MockWSHandler http.HandlerFunc // Set in mock mode to override /ws handler
	srv           *http.Server
}

// NewServer creates a new web server.
func NewServer(addr string, service ports.NetworkService) *Server {
	return &Server{
		Addr:    addr,
		Service: service,

		WSManager: NewManager(service),
		API:       NewAPI(service, service),
	}
}

// SetMockWSHandler replaces the /ws WebSocket handler with a mock implementation.
func (s *Server) SetMockWSHandler(h http.HandlerFunc) {
	s.MockWSHandler = h
}

// Run starts the server and the broadcaster.
func (s *Server) Run(ctx context.Context) error {
	// Start WS Manager
	s.WSManager.Start(ctx)

	// Setup Routes
	handler := SetupRoutes(s)

	s.srv = &http.Server{
		Addr:              s.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful Shutdown implementation
	go func() {
		<-ctx.Done()
		log.Println("Web Server shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Web Server shutdown error: %v", err)
		}
	}()

	log.Printf("Web server listening on %s", s.Addr)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// BroadcastLog sends a log message to all connected clients
func (s *Server) BroadcastLog(message string, level string) {
	s.WSManager.BroadcastLog(message, level)
}

// BroadcastAlert sends an alert object to all connected clients
func (s *Server) BroadcastAlert(alert domain.Alert) {
	s.WSManager.BroadcastAlert(alert)
}
