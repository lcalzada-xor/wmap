package server

import (
	"net/http"
)

func SetupRoutes(s *Server) http.Handler {
	mux := http.NewServeMux()

	// WebSocket endpoint
	mux.Handle("/ws", http.HandlerFunc(s.WSManager.HandleWebSocket))

	// Core API
	mux.Handle("/api/scan", http.HandlerFunc(s.ScanHandler.HandleScan))
	mux.Handle("/api/config", http.HandlerFunc(s.ConfigHandler.HandleGetConfig))
	mux.Handle("/api/config/persistence", http.HandlerFunc(s.ConfigHandler.HandleTogglePersistence))
	mux.Handle("/api/stats", http.HandlerFunc(s.ScanHandler.HandleGetStats))
	mux.Handle("/api/channels", http.HandlerFunc(s.ScanHandler.HandleChannels))
	mux.Handle("/api/interfaces", http.HandlerFunc(s.ScanHandler.HandleListInterfaces))

	return mux
}
