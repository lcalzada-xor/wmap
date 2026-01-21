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
	"github.com/lcalzada-xor/wmap/internal/telemetry"
)

// Constants for default paths
const (
	DefaultOUIDBPath      = "data/oui/ieee_oui.db"
	DefaultSignaturesPath = "data/signatures.json"
)

// Application holds the core components of the application.
// It acts as the Facade for the entire system, orchestrating services and infrastructure.
// Application holds the core components of the application.
// It acts as the Facade for the entire system, orchestrating services and infrastructure.
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
	VendorRepo         fingerprint.VendorRepository
	MockIntegration    interface{}

	// source channels for internal events
	sourceDeviceChan <-chan domain.Device
	sourceAlertChan  <-chan domain.Alert

	// Internal State
	monitorInterfaces []string
}

// New creates a new Application instance and bootstraps its components.
func New(cfg *config.Config) (*Application, error) {
	app := &Application{
		Config: cfg,
	}

	if err := app.bootstrap(); err != nil {
		return nil, fmt.Errorf("application bootstrap failed: %w", err)
	}

	return app, nil
}

// bootstrap orchestrates the initialization sequence.
func (app *Application) bootstrap() error {
	// 1. Foundation & Infrastructure
	telemetry.InitMetrics()

	systemStore, err := app.initStorage()
	if err != nil {
		return err
	}

	if err := app.initExternalData(); err != nil {
		log.Printf("Warning: hardware/device data initialization incomplete: %v", err)
	}

	// 2. Network Driver Setup
	if err := app.initNetworkDriver(); err != nil {
		return err
	}

	// 3. Domain Services
	sigMatcher := app.loadSignatures()

	// TODO: Technical debt - concrete implementations don't fully match ports interfaces
	// (missing context.Context parameters). Using type assertions as a temporary bridge.
	vulnStore := security.NewVulnerabilityPersistenceService(interface{}(systemStore).(ports.Storage))
	devRegistry := registry.NewDeviceRegistry(interface{}(sigMatcher).(ports.SignatureMatcher), vulnStore)
	securityEngine := security.NewSecurityEngine(interface{}(devRegistry).(ports.DeviceRegistry))

	app.PersistenceManager = persistence.NewPersistenceManager(interface{}(systemStore).(ports.Storage), 10000)

	if err := app.initWorkspace(devRegistry); err != nil {
		return err
	}

	app.AuditService = audit.NewAuditService(interface{}(systemStore).(ports.AuditRepository))
	app.AuthService = auth.NewAuthService(interface{}(systemStore).(ports.UserRepository))

	if err := app.ensureDefaultAdmin(systemStore); err != nil {
		log.Printf("Warning: could not ensure default admin: %v", err)
	}

	// 4. Networking & Engines
	if err := app.initNetworking(devRegistry, securityEngine); err != nil {
		return err
	}

	// 5. Servers & Integration
	app.initServers(vulnStore)

	if app.Config.MockMode {
		app.MockIntegration = "mock_enabled"
		log.Println("Mock Mode Active: Virtualizing network environment")
	}

	return nil
}

func (app *Application) initStorage() (*storage.SQLiteAdapter, error) {
	if err := os.MkdirAll(filepath.Dir(app.Config.DBPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create DB directory: %w", err)
	}

	store, err := storage.NewSQLiteAdapter(app.Config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init system storage: %w", err)
	}
	return store, nil
}

func (app *Application) initExternalData() error {
	// Initialize OUI Database with Caching
	ouiDB, err := fingerprint.NewOUIDatabase(DefaultOUIDBPath, 10000, nil)
	// We proceed even if err != nil (maybe DB missing), but we'll return it if critical
	// Ideally we want to use at least static/composite if DB fails.

	// Chain Repositories: Cached -> DB -> Static (fallback if DB unavailable or miss)
	// Actually Composite(Caching(DB), Static) could work too.
	// For now simple caching wrapper around DB.

	if err != nil {
		log.Printf("Warning: Failed to load OUI database: %v. Using static fallback.", err)
		// Fallback to static or nil?
		// We'll leave app.VendorRepo as nil? PacketHandler handles nil?
		// No, PacketHandler expects VendorRepo not nil.
		// Let's create a Static one empty or default.
		// For now let's just create a dummy if error.
		// A better architecture would be CompositeRepository that includes Static.
		// fingerprint.NewStaticVendorRepository(nil)
	}

	var baseRepo fingerprint.VendorRepository = ouiDB
	if ouiDB == nil {
		// Create empty static repo
		baseRepo = fingerprint.NewStaticVendorRepository(nil)
	}

	// Wrap with Cache
	cachedRepo := fingerprint.NewCachingRepository(20000, baseRepo)
	app.VendorRepo = cachedRepo

	return nil
}

func (app *Application) initNetworkDriver() error {
	if app.Config.MockMode {
		log.Println("Skipping network driver initialization (Mock Mode)")
		return nil
	}

	if len(app.Config.Interfaces) == 0 {
		return fmt.Errorf("no network interfaces configured")
	}

	log.Println("Stopping conflicting network services...")
	if err := driver.KillConflictingProcesses(); err != nil {
		log.Printf("Warning: Failed to stop conflicting processes: %v", err)
	}

	for _, iface := range app.Config.Interfaces {
		if err := driver.EnableMonitorMode(iface); err != nil {
			return fmt.Errorf("failed to enable monitor mode on %s: %v", iface, err)
		}
		app.monitorInterfaces = append(app.monitorInterfaces, iface)
	}

	time.Sleep(2 * time.Second) // Settle time
	return nil
}

func (app *Application) loadSignatures() *fingerprint.SignatureStore {
	sigData, err := os.ReadFile(DefaultSignaturesPath)
	if err != nil {
		log.Printf("Warning: Could not load signatures: %v", err)
		return nil
	}

	var sigs []domain.DeviceSignature
	if err := json.Unmarshal(sigData, &sigs); err != nil {
		log.Printf("Error parsing signatures: %v", err)
		return nil
	}

	log.Printf("Loaded %d device signatures", len(sigs))
	return fingerprint.NewSignatureStore(sigs)
}

func (app *Application) initWorkspace(reg *registry.DeviceRegistry) error {
	mgr, err := workspace.NewWorkspaceManager(app.Config.WorkspaceDir, app.PersistenceManager, interface{}(reg).(ports.DeviceRegistry))
	if err != nil {
		return fmt.Errorf("workspace initialization failed: %w", err)
	}
	app.WorkspaceManager = mgr
	return nil
}

func (app *Application) ensureDefaultAdmin(store *storage.SQLiteAdapter) error {
	if _, err := store.GetByUsername(context.Background(), "admin"); err != nil {
		log.Println("Provisioning default admin user...")
		return app.AuthService.CreateUser(context.Background(), domain.User{
			Username: "admin",
			Role:     domain.RoleAdmin,
		}, "changeit")
	}
	return nil
}

func (app *Application) initNetworking(reg *registry.DeviceRegistry, sec *security.SecurityEngine) error {
	locProvider := geo.NewStaticProvider(app.Config.Latitude, app.Config.Longitude)

	if app.Config.MockMode {
		deviceChan := make(chan domain.Device, 100)
		alertChan := make(chan domain.Alert, 100)
		mock := sniffer.NewMock(deviceChan, locProvider)
		// Cast to interface to satisfy ports.Sniffer
		app.SnifferRunner = interface{}(mock).(ports.Sniffer)
		app.sourceDeviceChan = deviceChan
		app.sourceAlertChan = alertChan
	} else {
		manager := sniffer.NewManager(app.Config.Interfaces, app.Config.DwellTime, app.Config.Debug, locProvider, app.VendorRepo)
		// Cast to interface to satisfy ports.Sniffer
		app.SnifferRunner = interface{}(manager).(ports.Sniffer)
		app.sourceDeviceChan = manager.Output
		app.sourceAlertChan = manager.Alerts
	}

	app.NetworkService = network.NewNetworkService(interface{}(reg).(ports.DeviceRegistry), interface{}(sec).(ports.SecurityEngine), app.PersistenceManager, interface{}(app.SnifferRunner).(ports.Sniffer), app.AuditService)
	app.configureEngines(reg)
	return nil
}

func (app *Application) configureEngines(reg *registry.DeviceRegistry) {
	var locker capture.ChannelLocker
	if manager, ok := app.SnifferRunner.(*sniffer.SnifferManager); ok {
		locker = manager
	}

	var defaultIface string
	if len(app.Config.Interfaces) > 0 {
		defaultIface = app.Config.Interfaces[0]
	}

	var injector *injection.Injector
	if manager, ok := app.SnifferRunner.(*sniffer.SnifferManager); ok {
		injector = manager.GetInjector(defaultIface)
	}

	if injector == nil && defaultIface != "" {
		var err error
		injector, err = injection.NewInjector(defaultIface)
		if err != nil {
			log.Printf("Warning: Failed to create injector: %v", err)
		}
	}

	// Setup Engines
	app.NetworkService.SetDeauthEngine(interface{}(deauth.NewDeauthEngine(injector, locker, 5)).(ports.DeauthService))

	wpsEngine := wps.NewWPSEngine(interface{}(reg).(ports.DeviceRegistry))
	if locker != nil {
		wpsEngine.SetChannelLocker(locker)
	}
	wpsEngine.SetToolPaths(app.Config.ReaverPath, app.Config.PixiewpsPath)
	app.NetworkService.SetWPSEngine(interface{}(wpsEngine).(ports.WPSAttackService))

	afEngine := authflood.NewAuthFloodEngine(injector, locker, 5)
	if app.Config.Debug {
		afEngine.SetLogger(func(msg, level string) {
			slog.Info("AUTH-FLOOD", "level", level, "msg", msg)
		})
	}
	app.NetworkService.SetAuthFloodEngine(afEngine)
}

func (app *Application) initServers(vulnStore *security.VulnerabilityPersistenceService) {
	app.WebServer = webserver.NewServer(app.Config.Addr, interface{}(app.NetworkService).(ports.NetworkService), app.WorkspaceManager, app.AuthService, app.AuditService, vulnStore)

	if app.WebServer.WSManager != nil {
		vulnStore.SetNotifier(interface{}(app.WebServer.WSManager).(ports.VulnerabilityNotifier))

		// Bridge logs to WS
		app.NetworkService.SetDeauthLogger(func(msg, level string) {
			app.WebServer.BroadcastLog(msg, level)
		})

		// Bridge WPS callbacks - need to store concrete type for this
		// TODO: Add SetCallbacks to ports.WPSAttackService interface
		if wpsIface := app.NetworkService.GetWPSEngine(); wpsIface != nil {
			// We know we passed a *wps.WPSEngine, so we can use unsafe cast via any
			if wpsEngine, ok := interface{}(wpsIface).(*wps.WPSEngine); ok {
				wpsEngine.SetCallbacks(
					app.WebServer.WSManager.BroadcastWPSLog,
					app.WebServer.WSManager.BroadcastWPSStatus,
				)
			}
		}
	}

	app.GrpcServer = grpcserver.NewGrpcServer(interface{}(app.NetworkService).(ports.NetworkService))
}

// Run starts the application components and manages their execution lifecycle.
func (app *Application) Run(ctx context.Context) error {
	slog.Info("Starting WMAP components...")

	// 1. Auxiliary Loops
	app.NetworkService.StartCleanupLoop(ctx, 10*time.Minute, 1*time.Minute)
	app.PersistenceManager.Start(ctx)

	// 2. Background Processing
	go app.runAlertPump(ctx)
	app.runDeviceWorkers(ctx)

	// 3. Servers & Sniffer
	errChan := make(chan error, 3)

	go func() {
		log.Printf("Web Server listening on %s", app.Config.Addr)
		if err := app.WebServer.Run(ctx); err != nil {
			errChan <- fmt.Errorf("web server error: %w", err)
		}
	}()

	go func() {
		log.Printf("gRPC Server listening on :%d", app.Config.GRPCPort)
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", app.Config.GRPCPort))
		if err != nil {
			errChan <- fmt.Errorf("grpc listen error: %w", err)
			return
		}

		go func() {
			<-ctx.Done()
			app.GrpcServer.GracefulStop()
		}()

		if err := app.GrpcServer.Serve(lis); err != nil {
			errChan <- fmt.Errorf("grpc server error: %w", err)
		}
	}()

	go func() {
		time.Sleep(1 * time.Second) // Wait for servers to bind
		if err := app.SnifferRunner.Start(ctx); err != nil {
			errChan <- fmt.Errorf("sniffer error: %w", err)
		}
	}()

	slog.Info("WMAP Ready. Press Ctrl+C to terminate.")

	select {
	case <-ctx.Done():
		slog.Info("Termination signal received")
	case err := <-errChan:
		return err
	}

	return app.cleanup()
}

func (app *Application) runAlertPump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-app.sourceAlertChan:
			slog.Info("Alert", "type", a.Type, "msg", a.Message)
			app.WebServer.BroadcastAlert(a)
		}
	}
}

func (app *Application) runDeviceWorkers(ctx context.Context) {
	numWorkers := runtime.NumCPU()
	slog.Info("Starting worker pool", "count", numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case d := <-app.sourceDeviceChan:
					if err := app.NetworkService.ProcessDevice(context.Background(), d); err != nil {
						log.Printf("Error processing device: %v", err)
					}
				}
			}
		}()
	}
}

func (app *Application) cleanup() error {
	slog.Info("Cleaning up resources...")

	if app.SnifferRunner != nil {
		app.SnifferRunner.Close()
	}

	if app.NetworkService != nil {
		if wpsEngine := app.NetworkService.GetWPSEngine(); wpsEngine != nil {
			wpsEngine.StopAll(context.Background())
		}
		app.NetworkService.Close()
	}

	return nil
}

// RestoreNetwork reverts changes made to network interfaces and services.
func (app *Application) RestoreNetwork() {
	if app.Config.MockMode {
		return
	}

	log.Println("Restoring networking infrastructure...")
	if err := driver.RestoreNetworkServices(); err != nil {
		log.Printf("Error restoring system services: %v", err)
	}

	for _, iface := range app.monitorInterfaces {
		driver.DisableMonitorMode(iface)
	}
}
