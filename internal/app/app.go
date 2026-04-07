package app

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/radio"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/mock"
	"github.com/lcalzada-xor/wmap/internal/adapters/storage"
	webserver "github.com/lcalzada-xor/wmap/internal/adapters/web"
	"github.com/lcalzada-xor/wmap/internal/config"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/network"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
	"github.com/lcalzada-xor/wmap/internal/core/services/registry"
	"github.com/lcalzada-xor/wmap/internal/core/services/security"
)

// Application is the main entry point for the WMAP application.
type Application struct {
	Config             *config.Config
	NetworkService     *network.NetworkService
	WebServer          *webserver.Server
	SnifferRunner      ports.Sniffer
	PersistenceManager ports.PersistenceService
	VendorRepo         fingerprint.VendorRepository
	MockIntegration    interface{}

	sourceDeviceChan  <-chan domain.Device
	sourceAlertChan   <-chan domain.Alert
	sourceEventChan   <-chan domain.ConnectionEvent
	monitorInterfaces []string
}

func New(cfg *config.Config) (*Application, error) {
	app := &Application{
		Config: cfg,
	}

	if err := app.bootstrap(); err != nil {
		return nil, fmt.Errorf("application bootstrap failed: %w", err)
	}

	return app, nil
}

func (app *Application) bootstrap() error {
	systemStore, err := app.initStorage()
	if err != nil {
		return err
	}

	if err := app.initExternalData(); err != nil {
		log.Printf("Warning: hardware/device data initialization incomplete: %v", err)
	}

	if err := app.initNetworkDriver(); err != nil {
		return err
	}

	sigMatcher := app.loadSignatures()
	devRegistry := registry.NewDeviceRegistry(sigMatcher)
	securityEngine := security.NewSecurityEngine(devRegistry)
	app.PersistenceManager = persistence.NewPersistenceManager(systemStore, 10000)

	if err := app.initNetworking(devRegistry, securityEngine); err != nil {
		return err
	}

	app.initServers(devRegistry)

	if app.Config.MockMode {
		app.MockIntegration = "mock_enabled"
		slog.Info("Mock Mode Active: Virtualizing network environment")
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
	// Initialize with static repository since external OUI database is not used
	baseRepo := fingerprint.NewStaticVendorRepository(nil)
	app.VendorRepo = fingerprint.NewCachingRepository(20000, baseRepo)
	return nil
}

func (app *Application) initNetworkDriver() error {
	if app.Config.MockMode {
		return nil
	}
	if len(app.Config.Interfaces) == 0 {
		return fmt.Errorf("no network interfaces configured")
	}

	driver.KillConflictingProcesses()

	// Track successfully configured interfaces for rollback
	successfulInterfaces := []string{}

	for _, iface := range app.Config.Interfaces {
		if err := driver.EnableMonitorMode(iface); err != nil {
			// If we fail, restore any interfaces we already configured
			slog.Warn("Failed to enable monitor mode, restoring previously configured interfaces...", "interface", iface)
			for _, successIface := range successfulInterfaces {
				driver.DisableMonitorMode(successIface)
			}
			// Also restore network services since we killed them
			driver.RestoreNetworkServices()
			return fmt.Errorf("failed to enable monitor mode on %s: %v", iface, err)
		}
		successfulInterfaces = append(successfulInterfaces, iface)
		app.monitorInterfaces = append(app.monitorInterfaces, iface)
	}

	time.Sleep(2 * time.Second)
	return nil
}

func (app *Application) loadSignatures() *fingerprint.SignatureStore {
	// Return empty signature store as external signatures file is no longer used
	return fingerprint.NewSignatureStore(nil)
}

func (app *Application) initNetworking(reg *registry.DeviceRegistry, sec *security.SecurityEngine) error {
	if app.Config.MockMode {
		deviceChan := make(chan domain.Device, 1000) // Increased buffer size
		alertChan := make(chan domain.Alert, 100)
		mockSniffer := mock.NewMock(deviceChan)
		app.SnifferRunner = mockSniffer
		app.sourceDeviceChan = deviceChan
		app.sourceAlertChan = alertChan
		app.sourceEventChan = make(chan domain.ConnectionEvent)
	} else {
		radioMgr := radio.NewRadioManager()
		manager := sniffer.NewManager(app.Config.Interfaces, app.Config.DwellTime, app.Config.Debug, app.VendorRepo, radioMgr, app.Config.HandshakeDir, app.Config.ChannelConfigPath, nil)
		app.SnifferRunner = manager
		app.sourceDeviceChan = manager.Output
		app.sourceAlertChan = manager.Alerts
		app.sourceEventChan = manager.Events
	}
	app.NetworkService = network.NewNetworkService(reg, sec, app.PersistenceManager, app.SnifferRunner)
	return nil
}

func (app *Application) initServers(devRegistry *registry.DeviceRegistry) {
	app.WebServer = webserver.NewServer(
		app.Config.Addr,
		app.NetworkService,
	)
}

func (app *Application) Run(ctx context.Context) error {
	slog.Info("Starting WMAP components...")

	var wg sync.WaitGroup

	app.NetworkService.StartCleanupLoop(ctx, 10*time.Minute, 1*time.Minute, 2*time.Minute)
	app.PersistenceManager.Start(ctx)

	wg.Add(1)
	go app.runAlertPump(ctx, &wg)

	wg.Add(1)
	go app.runEventWorker(ctx, &wg)

	app.runDeviceWorkers(ctx, &wg)

	errChan := make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := app.WebServer.Run(ctx); err != nil {
			errChan <- fmt.Errorf("web server error: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait a bit to ensure server is ready before starting capture
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return
		}

		if err := app.SnifferRunner.Start(ctx); err != nil {
			errChan <- fmt.Errorf("sniffer error: %w", err)
		}
	}()

	slog.Info("WMAP Ready. Press Ctrl+C to terminate.")

	var err error
	select {
	case <-ctx.Done():
		slog.Info("Termination signal received, shutting down gracefully...")
		if app.NetworkService != nil {
			app.NetworkService.Close()
		}
		if app.PersistenceManager != nil {
			app.PersistenceManager.Close()
		}
	case err = <-errChan:
		slog.Error("Critical component failure", "error", err)
	}

	// Graceful shutdown with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("All components stopped gracefully")
	case <-time.After(5 * time.Second):
		slog.Warn("Timed out waiting for components to stop, proceeding with cleanup")
	}

	if err != nil {
		return err
	}

	return app.cleanup()
}

func (app *Application) runAlertPump(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	slog.Debug("Alert pump started")
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Alert pump stopping")
			return
		case a := <-app.sourceAlertChan:
			slog.Info("Alert received", "type", a.Type, "msg", a.Message)
			app.WebServer.BroadcastAlert(a)
		}
	}
}

func (app *Application) runEventWorker(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if app.sourceEventChan == nil {
		return
	}
	slog.Debug("Event worker started")
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Event worker stopping")
			return
		case e := <-app.sourceEventChan:
			if app.PersistenceManager != nil {
				app.PersistenceManager.PersistEvent(e)
			}
		}
	}
}

func (app *Application) runDeviceWorkers(ctx context.Context, wg *sync.WaitGroup) {
	numWorkers := runtime.NumCPU()
	slog.Debug("Starting device workers", "count", numWorkers)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					slog.Debug("Device worker stopping", "id", workerID)
					return
				case d := <-app.sourceDeviceChan:
					if err := app.NetworkService.ProcessDevice(ctx, d); err != nil {
						slog.Error("Failed to process device", "error", err, "mac", d.MAC)
					}
				}
			}
		}(i)
	}
}

func (app *Application) cleanup() error {
	if app.SnifferRunner != nil {
		app.SnifferRunner.Close()
	}
	return nil
}

func (app *Application) RestoreNetwork() {
	if app.Config.MockMode {
		return
	}
	driver.RestoreNetworkServices()
	for _, iface := range app.monitorInterfaces {
		driver.DisableMonitorMode(iface)
	}
}
