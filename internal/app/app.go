package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"google.golang.org/grpc"

	"github.com/lcalzada-xor/wmap/internal/adapters/attack/authflood"
	"github.com/lcalzada-xor/wmap/internal/adapters/attack/deauth"
	"github.com/lcalzada-xor/wmap/internal/adapters/attack/wps"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/adapters/storage"
	webserver "github.com/lcalzada-xor/wmap/internal/adapters/web/server"
	"github.com/lcalzada-xor/wmap/internal/config"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/audit"
	"github.com/lcalzada-xor/wmap/internal/core/services/auth"
	grpcserver "github.com/lcalzada-xor/wmap/internal/core/services/grpc"
	"github.com/lcalzada-xor/wmap/internal/core/services/network"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
	"github.com/lcalzada-xor/wmap/internal/core/services/registry"
	"github.com/lcalzada-xor/wmap/internal/core/services/security"
	"github.com/lcalzada-xor/wmap/internal/core/services/workspace"
	"github.com/lcalzada-xor/wmap/internal/geo"
)

// Application holds the core components of the application
type Application struct {
	Config             *config.Config
	NetworkService     *network.NetworkService
	WebServer          *webserver.Server
	GrpcServer         *grpc.Server
	SnifferRunner      ports.Sniffer
	WorkspaceManager   *workspace.WorkspaceManager
	AuthService        *auth.AuthService
	AuditService       *audit.AuditService
	PersistenceManager *persistence.PersistenceManager

	// Channels
	DeviceChan       chan domain.Device
	AlertChan        chan domain.Alert
	sourceDeviceChan <-chan domain.Device
	sourceAlertChan  <-chan domain.Alert

	// Internal State
	monitorInterfaces []string
}

// New creates a new Application instance
func New(cfg *config.Config) (*Application, error) {
	app := &Application{
		Config:     cfg,
		DeviceChan: make(chan domain.Device, 100),
		AlertChan:  make(chan domain.Alert, 100),
	}

	if err := app.bootstrap(); err != nil {
		return nil, err
	}

	return app, nil
}

func (app *Application) bootstrap() error {
	// Initialize OUI Database
	ouiDBPath := "data/oui/ieee_oui.db"
	if err := fingerprint.InitOUIDatabase(ouiDBPath, 10000); err != nil {
		log.Printf("Warning: OUI database initialization failed: %v. Using fallback static map.", err)
	}

	// Enable Monitor Mode (if not mocking)
	if !app.Config.MockMode {
		if len(app.Config.Interfaces) == 0 {
			return fmt.Errorf("no interfaces configured")
		}

		// Proactively kill conflicting processes
		log.Println("Stopping conflicting network services (NetworkManager, wpa_supplicant)...")
		if err := driver.KillConflictingProcesses(); err != nil {
			log.Printf("Warning: Failed to stop conflicting processes: %v", err)
			log.Printf("Monitor mode might be unstable.")
		}

		for _, iface := range app.Config.Interfaces {
			if err := driver.EnableMonitorMode(iface); err != nil {
				return fmt.Errorf("failed to enable monitor mode on %s: %v", iface, err)
			}
			app.monitorInterfaces = append(app.monitorInterfaces, iface)
		}

		// Wait for interfaces to settle
		log.Println("Waiting for interface(s) to settle...")
		time.Sleep(2 * time.Second)
	} else {
		log.Println("Running in MOCK MODE. No real packets will be captured.")
	}

	// Location Provider
	locProvider := geo.NewStaticProvider(app.Config.Latitude, app.Config.Longitude)

	// Sniffer Setup
	if app.Config.MockMode {
		mock := sniffer.NewMock(app.DeviceChan, locProvider)
		app.SnifferRunner = mock
		app.sourceDeviceChan = app.DeviceChan
		app.sourceAlertChan = app.AlertChan
	} else {
		manager := sniffer.NewManager(app.Config.Interfaces, app.Config.DwellTime, app.Config.Debug, locProvider)
		app.SnifferRunner = manager
		app.sourceDeviceChan = manager.Output
		app.sourceAlertChan = manager.Alerts
	}

	// Load Signatures
	var sigMatcher ports.SignatureMatcher
	sigData, err := os.ReadFile("data/signatures.json")
	if err != nil {
		log.Printf("Warning: Could not load signatures: %v", err)
	} else {
		var sigs []domain.DeviceSignature
		if err := json.Unmarshal(sigData, &sigs); err != nil {
			log.Printf("Error parsing signatures: %v", err)
		} else {
			sigMatcher = fingerprint.NewSignatureStore(sigs)
			log.Printf("Loaded %d device signatures", len(sigs))
		}
	}

	// Core Services Initialization
	devRegistry := registry.NewDeviceRegistry(sigMatcher)
	securityEngine := security.NewSecurityEngine(devRegistry)
	app.PersistenceManager = persistence.NewPersistenceManager(nil, 10000)

	// Workspace Manager
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to resolve home directory: %v", err)
	}
	workspaceDir := filepath.Join(home, ".local", "share", "wmap", "workspaces")
	log.Printf("Workspace Storage Path: %s", workspaceDir)

	workspaceManager, err := workspace.NewWorkspaceManager(workspaceDir, app.PersistenceManager, devRegistry)
	if err != nil {
		return fmt.Errorf("failed to initialize Workspace Manager: %v", err)
	}
	app.WorkspaceManager = workspaceManager

	// System Services (DB, Auth, Audit)
	systemDBPath := filepath.Join(home, ".local", "share", "wmap", "system.db")
	os.MkdirAll(filepath.Dir(systemDBPath), 0755)

	systemStore, err := storage.NewSQLiteAdapter(systemDBPath)
	if err != nil {
		return fmt.Errorf("failed to init system DB: %v", err)
	}

	// Connect PersistenceManager to Storage
	app.PersistenceManager.SetStorage(systemStore)

	auditService := audit.NewAuditService(systemStore)
	authService := auth.NewAuthService(systemStore)
	app.AuditService = auditService
	app.AuthService = authService

	// Create default admin
	if _, err := systemStore.GetByUsername("admin"); err != nil {
		log.Println("Creating default admin user...")
		err = authService.CreateUser(context.Background(), domain.User{
			Username: "admin",
			Role:     domain.RoleAdmin,
		}, "changeit")
		if err != nil {
			log.Printf("Failed to create admin user: %v", err)
		}
	}

	// Network Service
	networkService := network.NewNetworkService(devRegistry, securityEngine, app.PersistenceManager, app.SnifferRunner, auditService)
	app.NetworkService = networkService

	// Web Server
	app.WebServer = webserver.NewServer(app.Config.Addr, networkService, workspaceManager, authService, auditService)

	// Configure Engines (Deauth, WPS, AuthFlood)
	// We pass Registry explicitly
	app.configureEngines(networkService, devRegistry)

	// gRPC Server
	app.GrpcServer = grpcserver.NewGrpcServer(networkService)

	return nil
}

func (app *Application) configureEngines(ns *network.NetworkService, devRegistry *registry.DeviceRegistry) {
	// Deauth Engine
	var locker capture.ChannelLocker
	if manager, ok := app.SnifferRunner.(*sniffer.SnifferManager); ok {
		locker = manager
	}

	var defaultInterface string
	if len(app.Config.Interfaces) > 0 {
		defaultInterface = app.Config.Interfaces[0]
	}

	var injector *injection.Injector
	var errInj error

	if manager, ok := app.SnifferRunner.(*sniffer.SnifferManager); ok {
		injector = manager.GetInjector(defaultInterface)
	}

	if injector == nil {
		injector, errInj = injection.NewInjector(defaultInterface)
		if errInj != nil {
			log.Printf("Warning: Failed to create default injector: %v", errInj)
		}
	}

	deauthEngine := deauth.NewDeauthEngine(injector, locker, 5)
	ns.SetDeauthEngine(deauthEngine)

	// WPS Engine
	wpsEngine := wps.NewWPSEngine(devRegistry)
	if locker != nil {
		wpsEngine.SetChannelLocker(locker)
	}
	// Set paths
	wpsEngine.SetToolPaths(app.Config.ReaverPath, app.Config.PixiewpsPath)
	// Set Callbacks via WebServer WSManager
	wpsEngine.SetCallbacks(
		app.WebServer.WSManager.BroadcastWPSLog,
		app.WebServer.WSManager.BroadcastWPSStatus,
	)
	ns.SetWPSEngine(wpsEngine)

	// Auth Flood Engine
	authFloodEngine := authflood.NewAuthFloodEngine(injector, locker, 5)
	if app.Config.Debug {
		authFloodEngine.SetLogger(func(msg, level string) {
			slog.Info("AUTH-FLOOD", "level", level, "msg", msg)
		})
	}
	ns.SetAuthFloodEngine(authFloodEngine)

	// Set Deauth Logger to bridge logs to WebSocket
	ns.SetDeauthLogger(func(msg, level string) {
		app.WebServer.BroadcastLog(msg, level)
	})
}

// Run starts the application components
func (app *Application) Run(ctx context.Context) error {
	// Start Cleanup Loop
	app.NetworkService.StartCleanupLoop(ctx, 10*time.Minute, 1*time.Minute)

	// Start Persistence
	app.PersistenceManager.Start(ctx)

	// Add Example Rules
	app.NetworkService.AddRule(domain.AlertRule{
		ID:      "apple-device",
		Type:    domain.AlertVendor,
		Value:   "Apple",
		Enabled: true,
	})

	// Background Processing
	// 1. Alert Pump
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case a := <-app.sourceAlertChan:
				slog.Info("ALERT RECEIVED", "type", a.Type, "msg", a.Message)
				app.WebServer.BroadcastAlert(a)
			}
		}
	}()

	// 2. Device Worker Pool
	numWorkers := runtime.NumCPU()
	slog.Info("Starting packet processing worker pool", "workers", numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func(id int) {
			for {
				select {
				case <-ctx.Done():
					return
				case d := <-app.sourceDeviceChan:
					app.NetworkService.ProcessDevice(d)
				}
			}
		}(i)
	}

	// Error channel
	errChan := make(chan error, 1)

	// Start Web Server
	go func() {
		log.Printf("Starting Web Server on %s", app.Config.Addr)
		if err := app.WebServer.Run(ctx); err != nil {
			log.Printf("Web Server error: %v", err)
			errChan <- err
		}
	}()

	// Start gRPC Server
	go func() {
		log.Printf("Starting gRPC Server on :%d", app.Config.GRPCPort)
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", app.Config.GRPCPort))
		if err != nil {
			log.Printf("Failed to listen for gRPC: %v", err)
			errChan <- err
			return
		}

		// Graceful Stop
		go func() {
			<-ctx.Done()
			app.GrpcServer.GracefulStop()
		}()

		if err := app.GrpcServer.Serve(lis); err != nil {
			log.Printf("gRPC Server error: %v", err)
			errChan <- err
		}
	}()

	// Start Sniffer
	go func() {
		time.Sleep(1 * time.Second)
		if err := app.SnifferRunner.Start(ctx); err != nil {
			slog.Error("Sniffer failed", "error", err)
			errChan <- err
		} else {
			slog.Info("Sniffer stopped")
		}
	}()

	slog.Info("WMAP Started. Press Ctrl+C to exit")

	// Wait for shutdown or error
	select {
	case <-ctx.Done():
		slog.Info("Shutdown signal received")
	case err := <-errChan:
		return err
	}

	// Cleanup
	slog.Info("Cleaning up resources...")
	if app.SnifferRunner != nil {
		app.SnifferRunner.Close()
	}
	if app.NetworkService != nil {
		app.NetworkService.Close()
	}

	time.Sleep(1 * time.Second)
	slog.Info("Shutting down...")
	return nil
}

func (app *Application) RestoreNetwork() {
	if !app.Config.MockMode {
		log.Println("Restoring network services...")
		if err := driver.RestoreNetworkServices(); err != nil {
			log.Printf("Error restoring network services: %v", err)
		}
		for _, iface := range app.monitorInterfaces {
			driver.DisableMonitorMode(iface)
		}
	}
}
