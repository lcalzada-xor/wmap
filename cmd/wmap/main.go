package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/lcalzada-xor/wmap/geo"
	"github.com/lcalzada-xor/wmap/internal/adapters/attack"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/adapters/storage"
	"github.com/lcalzada-xor/wmap/internal/adapters/web"
	"github.com/lcalzada-xor/wmap/internal/config"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services"
)

func main() {
	// Setup Structured Logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Root Context with cancellation on Interrupt
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("WMAP Starting...")

	// Load Configuration
	cfg := config.Load()

	// Initialize OUI Database
	ouiDBPath := "data/oui/ieee_oui.db"
	if err := sniffer.InitOUIDatabase(ouiDBPath, 10000); err != nil {
		log.Printf("Warning: OUI database initialization failed: %v. Using fallback static map.", err)
	}

	// Enable Monitor Mode (if not mocking)
	// Enable Monitor Mode (if not mocking)
	if !cfg.MockMode {
		if len(cfg.Interfaces) == 0 {
			log.Fatalf("No interfaces configured")
		}

		// Proactively kill conflicting processes (NetworkManager, wpa_supplicant)
		log.Println("Stopping conflicting network services (NetworkManager, wpa_supplicant)...")
		if err := sniffer.KillConflictingProcesses(); err != nil {
			log.Printf("Warning: Failed to stop conflicting processes: %v", err)
			log.Printf("Monitor mode might be unstable.")
		}

		// Ensure we restore services when we exit (even on panic or signal)
		defer func() {
			log.Println("Restoring network services...")
			if err := sniffer.RestoreNetworkServices(); err != nil {
				log.Printf("Error restoring network services: %v", err)
			} else {
				log.Println("Network services restored.")
			}
		}()

		for _, iface := range cfg.Interfaces {
			if err := enableMonitorMode(iface); err != nil {
				log.Fatalf("Failed to enable monitor mode on %s: %v", iface, err)
			}
			defer disableMonitorMode(iface) // Ensure we switch back on any exit
		}

		// Wait for interfaces to settle
		log.Println("Waiting for interface(s) to settle...")
		time.Sleep(2 * time.Second)
	} else {
		log.Println("Running in MOCK MODE. No real packets will be captured.")
	}

	// Channel for device events
	deviceChan := make(chan domain.Device, 100)
	alertChan := make(chan domain.Alert, 100)

	// Location Provider
	// In the future, this could be swapped for a GPS provider
	locProvider := geo.NewStaticProvider(cfg.Latitude, cfg.Longitude)

	// Persistence logic moved to SessionManager
	// We no longer initialize 'store' here directly from cfg.DBPath.
	// sessions/ logic will handle it.

	// Sniffer (Mock or Real)
	// Sniffer (Mock or Real) using Manager
	var runnable ports.Sniffer // Use Port Interface
	// We use SnifferManager here. It implements Start but not explicitly ports.Sniffer?
	// ports.Sniffer interface is likely just Start(ctx) error. Let's check.
	// We read ports/signature.go earlier but not sniffer port.
	// However, SnifferManager has Start(ctx) error signature. It should fit.

	// We need to capture the output channels from the runnable
	var sourceDeviceChan <-chan domain.Device
	var sourceAlertChan <-chan domain.Alert

	if cfg.MockMode {
		mock := sniffer.NewMock(deviceChan, locProvider)
		runnable = mock
		// The mock writes to deviceChan directly as passed in NewMock
		// So we can just use deviceChan we created earlier
		sourceDeviceChan = deviceChan
		sourceAlertChan = alertChan // Mock doesn't seem to use alertChan in NewMock call above?
		// Wait, NewMock(deviceChan...) takes deviceChan.
		// We need to unify how we consume.
		// Let's look at lines 83-87 in original: New(..., deviceChan, alertChan, ...)
		// The single sniffer took channels as arguments.
		// The Manager creates its own channels.
		// For consistency, if we use Manager, we should read from Manager.Output.
		// For Mock, if it takes channel, we read from that channel.
	} else {
		// NewManager creates its own output channels
		manager := sniffer.NewManager(cfg.Interfaces, cfg.DwellTime, cfg.Debug, locProvider)
		runnable = manager
		sourceDeviceChan = manager.Output
		sourceAlertChan = manager.Alerts
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
			sigMatcher = sniffer.NewSignatureStore(sigs)
			log.Printf("Loaded %d device signatures", len(sigs))
		}
	}

	// 1. Initialize Registry
	registry := services.NewDeviceRegistry(sigMatcher)

	// 2. Initialize Security Engine
	security := services.NewSecurityEngine(registry)

	// 3. Initialize Persistence Manager (Start with no storage, SessionManager will set it)
	persistence := services.NewPersistenceManager(nil, 10000)

	// 4. Initialize Workspace Manager (formerly Session Manager)
	// Use XDG compliant path: ~/.local/share/wmap/workspaces
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to resolve home directory: %v", err)
	}
	workspaceDir := filepath.Join(home, ".local", "share", "wmap", "workspaces")
	log.Printf("Workspace Storage Path: %s", workspaceDir)

	workspaceManager, err := services.NewWorkspaceManager(workspaceDir, persistence, registry)
	if err != nil {
		log.Fatalf("Failed to initialize Workspace Manager: %v", err)
	}
	defer workspaceManager.Close()

	// 5. Initialize System Services (DB, Auth, Audit)
	systemDBPath := filepath.Join(home, ".local", "share", "wmap", "system.db")
	os.MkdirAll(filepath.Dir(systemDBPath), 0755)

	systemStore, err := storage.NewSQLiteAdapter(systemDBPath)
	if err != nil {
		log.Fatalf("Failed to init system DB: %v", err)
	}

	auditService := services.NewAuditService(systemStore)
	authService := services.NewAuthService(systemStore)

	// Create default admin if not exists
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

	// 6. Initialize Network Service (Orchestrator)
	networkService := services.NewNetworkService(registry, security, persistence, runnable, auditService)

	// Initialize Deauth Engine
	// Currently relying on the main SnifferManager which implements ChannelLocker
	// If runnable is Mock, it might not implement ChannelLocker properly, checking...
	var locker sniffer.ChannelLocker
	if manager, ok := runnable.(*sniffer.SnifferManager); ok {
		locker = manager
	}
	// Note: If mock, locker is nil, which is handled gracefully by engine (just no locking)

	// Use the first interface for deauth injection by default, or find specific one.
	// Injector needs an interface name.
	var defaultInterface string
	if len(cfg.Interfaces) > 0 {
		defaultInterface = cfg.Interfaces[0]
	}

	// Create a dedicated injector or share one?
	// DeauthEngine creates its own if interface specified in attack config.
	// But it needs a base one.
	var injector *sniffer.Injector
	var errInj error

	// Try to reuse injector from manager to avoid multiple handles/resource busy
	if manager, ok := runnable.(*sniffer.SnifferManager); ok {
		injector = manager.GetInjector(defaultInterface)
		if injector != nil {
			log.Printf("Reusing Sniffer injector for %s", defaultInterface)
		}
	}

	// Fallback to creating a new one if not found or not using manager
	if injector == nil {
		injector, errInj = sniffer.NewInjector(defaultInterface)
		if errInj != nil {
			log.Printf("Warning: Failed to create default injector: %v", errInj)
		}
	}

	deauthEngine := sniffer.NewDeauthEngine(injector, locker, 5)
	networkService.SetDeauthEngine(deauthEngine)

	// Initialize WPS Engine
	// We create a new engine instance. It doesn't need external deps other than reaver in path
	wpsEngine := attack.NewWPSEngine(registry)
	if locker != nil {
		wpsEngine.SetChannelLocker(locker)
	}
	networkService.SetWPSEngine(wpsEngine)

	// Initialize Auth Flood Engine
	authFloodEngine := sniffer.NewAuthFloodEngine(injector, locker, 5)
	if cfg.Debug {
		authFloodEngine.SetLogger(func(msg, level string) {
			slog.Info("AUTH-FLOOD", "level", level, "msg", msg)
		})
	}
	networkService.SetAuthFloodEngine(authFloodEngine)

	// Start Cleanup Loop: Remove devices unseen for 10m, check every 1m
	networkService.StartCleanupLoop(ctx, 10*time.Minute, 1*time.Minute)

	// Start Persistence Loop
	persistence.Start(ctx)

	// Add Example Rules
	networkService.AddRule(domain.AlertRule{
		ID:      "apple-device",
		Type:    domain.AlertVendor,
		Value:   "Apple",
		Enabled: true,
	})
	networkService.AddRule(domain.AlertRule{
		ID:      "hidden-lab-probe",
		Type:    domain.AlertProbe,
		Value:   "HiddenLab",
		Enabled: true,
	})

	// PUMP: Channel -> Service
	// 6. Web Server (Create early to use in pump)
	// PUMP: Channel -> Service
	// 6. Web Server (Create early to use in pump)
	server := web.NewServer(cfg.Addr, networkService, workspaceManager, authService, auditService)

	// PUMP: Channel -> Service
	// 1. Alert Pump (Dedicated)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case a := <-sourceAlertChan:
				slog.Info("ALERT RECEIVED", "type", a.Type, "msg", a.Message)
				server.BroadcastAlert(a)
			}
		}
	}()

	// 2. Device Worker Pool (Parallel Processing)
	numWorkers := runtime.NumCPU()
	slog.Info("Starting packet processing worker pool", "workers", numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func(id int) {
			for {
				select {
				case <-ctx.Done():
					return
				case d := <-sourceDeviceChan:
					networkService.ProcessDevice(d)
				}
			}
		}(i)
	}

	// Web Server
	// server := web.NewServer(cfg.Addr, networkService, sessionManager)

	// Error channel to catch failures
	errChan := make(chan error, 1)

	// Start Web Server in goroutine
	go func() {
		log.Printf("Starting Web Server on %s", cfg.Addr)

		// Set Deauth Logger to bridge logs to WebSocket
		// We do this here to ensure server is ready (though methods are safe)
		networkService.SetDeauthLogger(func(msg, level string) {
			server.BroadcastLog(msg, level)
		})

		// Run(ctx) handles graceful shutdown internally
		if err := server.Run(ctx); err != nil {
			log.Printf("Web Server error: %v", err)
			errChan <- err
		}
	}()

	// Wire up WPS Engine callbacks to WebSockets
	// Note: We do this after server is created but before attacks start
	wpsEngine.SetCallbacks(
		server.WSManager.BroadcastWPSLog,
		server.WSManager.BroadcastWPSStatus,
	)
	wpsEngine.SetToolPaths(cfg.ReaverPath, cfg.PixiewpsPath)

	// Start gRPC Server
	go func() {
		log.Printf("Starting gRPC Server on :%d", cfg.GRPCPort)
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
		if err != nil {
			log.Printf("Failed to listen for gRPC: %v", err)
			errChan <- err
			return
		}
		grpcServer := services.NewGrpcServer(networkService)

		// Graceful Stop on Context
		go func() {
			<-ctx.Done()
			grpcServer.GracefulStop()
		}()

		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC Server error: %v", err)
			errChan <- err
		}
	}()

	// Start Channel Hopper (Managed by SnifferManager now)
	// if !cfg.MockMode && hopper != nil {
	// 	go hopper.Start()
	// }

	// Start Sniffer
	go func() {
		// Extra safety wait
		time.Sleep(1 * time.Second)
		if err := runnable.Start(ctx); err != nil {
			slog.Error("Sniffer failed", "error", err)
			errChan <- err
		} else {
			// Sniffer finished gracefully
			slog.Info("Sniffer stopped")
		}
	}()

	slog.Info("WMAP Started. Press Ctrl+C to exit")

	// Wait for context done or error
	select {
	case <-ctx.Done():
		slog.Info("Shutdown signal received")
	case err := <-errChan:
		slog.Error("Fatal error encountered", "error", err)
		cancel() // Cancel context to stop other components
	}

	// Grace period for cleanup
	time.Sleep(1 * time.Second)
	slog.Info("Shutting down...")
}

func enableMonitorMode(iface string) error {
	log.Printf("Enabling monitor mode on %s...", iface)
	// ip link set <iface> down
	if err := runCmd("ip", "link", "set", iface, "down"); err != nil {
		return err
	}
	// iw <iface> set type monitor
	if err := runCmd("iw", iface, "set", "type", "monitor"); err != nil {
		log.Printf("Error setting monitor mode. Trying to help...")
		log.Printf("Hint: If you see 'Device or resource busy', you may need to kill conflicting processes.")
		log.Printf("Run 'sudo airmon-ng check kill' and try again.")
		return err
	}
	// Set channel 6 (common, helps ensuring card is listening somewhere)
	// We ignore error here as it's not critical if it fails (card might auto-hop)
	runCmd("iw", iface, "set", "channel", "6")

	// ip link set <iface> up
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		return err
	}
	return nil
}

func disableMonitorMode(iface string) {
	log.Printf("Restoring managed mode on %s...", iface)
	// ip link set <iface> down
	runCmd("ip", "link", "set", iface, "down")
	// iw <iface> set type managed
	runCmd("iw", iface, "set", "type", "managed")
	// ip link set <iface> up
	runCmd("ip", "link", "set", iface, "up")
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command failed: %s %v\nOutput: %s", name, args, string(output))
		return err
	}
	return nil
}
