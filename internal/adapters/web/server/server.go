package server

import (
	"context"
	"log"
	"net/http"

	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/reporting"
	"github.com/lcalzada-xor/wmap/internal/adapters/web"
	"github.com/lcalzada-xor/wmap/internal/adapters/web/handlers"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	reportingService "github.com/lcalzada-xor/wmap/internal/core/services/reporting"
	"github.com/lcalzada-xor/wmap/internal/core/services/security"
	"github.com/lcalzada-xor/wmap/internal/core/services/workspace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Server handles HTTP and WebSocket connections.
type Server struct {
	Addr             string
	Service          ports.NetworkService
	WorkspaceManager *workspace.WorkspaceManager
	AuthService      ports.AuthService
	AuditService     ports.AuditService
	WSManager        *web.WSManager
	WPSHandler       *handlers.WPSHandler

	DeauthHandler    *handlers.DeauthHandler
	AuthFloodHandler *handlers.AuthFloodHandler
	AuditHandler     *handlers.AuditHandler
	ReportHandler    *handlers.ReportHandler
	AuthHandler      *handlers.AuthHandler
	ScanHandler      *handlers.ScanHandler
	ConfigHandler    *handlers.ConfigHandler
	WorkspaceHandler *handlers.WorkspaceHandler
	ExportHandler    *handlers.ExportHandler
	VulnHandler      *handlers.VulnerabilityHandler
	CaptureHandler   *handlers.CaptureHandler
	srv              *http.Server
}

// NewServer creates a new web server.
func NewServer(addr string, service ports.NetworkService, workspaceManager *workspace.WorkspaceManager, authService ports.AuthService, auditService ports.AuditService, vulnService *security.VulnerabilityPersistenceService, executiveGenerator *reportingService.ExecutiveReportGenerator, pdfExporter *reporting.PDFExporter) *Server {
	reportHandler := handlers.NewReportHandler(service, auditService, workspaceManager)
	reportHandler.ExecutiveGenerator = executiveGenerator
	reportHandler.PDFExporter = pdfExporter

	return &Server{
		Addr:             addr,
		Service:          service,
		WorkspaceManager: workspaceManager,
		AuthService:      authService,
		AuditService:     auditService,

		WSManager:        web.NewWSManager(service),
		WPSHandler:       handlers.NewWPSHandler(service),
		DeauthHandler:    handlers.NewDeauthHandler(service),
		AuthFloodHandler: handlers.NewAuthFloodHandler(service),
		AuditHandler:     handlers.NewAuditHandler(auditService),
		ReportHandler:    reportHandler,
		AuthHandler:      handlers.NewAuthHandler(authService),
		ScanHandler:      handlers.NewScanHandler(service),
		ConfigHandler:    handlers.NewConfigHandler(service),
		WorkspaceHandler: handlers.NewWorkspaceHandler(service, workspaceManager),
		ExportHandler:    handlers.NewExportHandler(service),
		VulnHandler:      handlers.NewVulnerabilityHandler(vulnService),
		CaptureHandler:   handlers.NewCaptureHandler(),
	}
}

// Run starts the server and the broadcaster.
func (s *Server) Run(ctx context.Context) error {
	// Start WS Manager
	s.WSManager.Start(ctx)

	// Setup Routes
	handler := SetupRoutes(s)

	// Instrument with OpenTelemetry
	// "wmap-server" is the name of the operation (span)
	instrumentedHandler := otelhttp.NewHandler(handler, "wmap-server")

	s.srv = &http.Server{
		Addr:              s.Addr,
		Handler:           instrumentedHandler,
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
