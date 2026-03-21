package app

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/radio"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/mock"
	"github.com/lcalzada-xor/wmap/internal/adapters/storage"
	webserver "github.com/lcalzada-xor/wmap/internal/adapters/web/server"
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
	PersistenceManager *persistence.PersistenceManager
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
	devRegistry := registry.NewDeviceRegistry(interface{}(sigMatcher).(ports.SignatureMatcher))
	securityEngine := security.NewSecurityEngine(interface{}(devRegistry).(ports.DeviceRegistry))
	app.PersistenceManager = persistence.NewPersistenceManager(interface{}(systemStore).(ports.Storage), 10000)

	if err := app.initNetworking(devRegistry, securityEngine); err != nil {
		return err
	}

	app.initServers(systemStore, devRegistry)

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
			log.Printf("Failed to enable monitor mode on %s, restoring previously configured interfaces...", iface)
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
		deviceChan := make(chan domain.Device, 100)
		alertChan := make(chan domain.Alert, 100)
		mockSniffer := mock.NewMock(deviceChan)
		app.SnifferRunner = interface{}(mockSniffer).(ports.Sniffer)
		app.sourceDeviceChan = deviceChan
		app.sourceAlertChan = alertChan
		app.sourceEventChan = make(chan domain.ConnectionEvent)
	} else {
		radioMgr := radio.NewRadioManager()
		manager := sniffer.NewManager(app.Config.Interfaces, app.Config.DwellTime, app.Config.Debug, app.VendorRepo, radioMgr, app.Config.HandshakeDir, app.Config.ChannelConfigPath)
		app.SnifferRunner = interface{}(manager).(ports.Sniffer)
		app.sourceDeviceChan = manager.Output
		app.sourceAlertChan = manager.Alerts
		app.sourceEventChan = manager.Events
	}
	app.NetworkService = network.NewNetworkService(interface{}(reg).(ports.DeviceRegistry), interface{}(sec).(ports.SecurityEngine), app.PersistenceManager, interface{}(app.SnifferRunner).(ports.Sniffer))
	return nil
}

func (app *Application) initServers(systemStore *storage.SQLiteAdapter, devRegistry *registry.DeviceRegistry) {
	app.WebServer = webserver.NewServer(
		app.Config.Addr,
		interface{}(app.NetworkService).(ports.NetworkService),
	)
}

func (app *Application) Run(ctx context.Context) error {
	slog.Info("Starting WMAP components...")

	app.NetworkService.StartCleanupLoop(ctx, 10*time.Minute, 1*time.Minute)
	app.PersistenceManager.Start(ctx)

	go app.runAlertPump(ctx)
	go app.runEventWorker(ctx)
	app.runDeviceWorkers(ctx)

	errChan := make(chan error, 3)

	go func() {
		if err := app.WebServer.Run(ctx); err != nil {
			errChan <- fmt.Errorf("web server error: %w", err)
		}
	}()

	go func() {
		time.Sleep(1 * time.Second)
		if err := app.SnifferRunner.Start(ctx); err != nil {
			errChan <- fmt.Errorf("sniffer error: %w", err)
		}
	}()

	slog.Info("WMAP Ready. Press Ctrl+C to terminate.")

	select {
	case <-ctx.Done():
		slog.Info("Termination signal received")
		if app.NetworkService != nil {
			app.NetworkService.Close()
		}
		time.Sleep(1 * time.Second)
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

func (app *Application) runEventWorker(ctx context.Context) {
	if app.sourceEventChan == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-app.sourceEventChan:
			if app.PersistenceManager != nil {
				app.PersistenceManager.PersistEvent(e)
			}
		}
	}
}

func (app *Application) runDeviceWorkers(ctx context.Context) {
	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case d := <-app.sourceDeviceChan:
					app.NetworkService.ProcessDevice(context.Background(), d)
				}
			}
		}()
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
