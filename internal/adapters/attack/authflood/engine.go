package authflood

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Common errors
var (
	ErrTargetBSSIDRequired  = errors.New("target BSSID is required")
	ErrTargetSSIDRequired   = errors.New("target SSID is required for Association Flood")
	ErrMaxConcurrentReached = errors.New("maximum concurrent attacks reached")
	ErrAttackNotFound       = errors.New("attack not found")
	ErrAttackNotActive      = errors.New("attack is not active")
	ErrNoInjectorAvailable  = errors.New("no injector available")
)

// AuthFloodController manages the lifecycle of a single auth flood attack
type AuthFloodController struct {
	ID       string
	Config   domain.AuthFloodAttackConfig
	Status   domain.AuthFloodAttackStatus
	CancelFn context.CancelFunc
	StatusCh chan domain.AuthFloodAttackStatus
	mu       sync.RWMutex
	injector *injection.Injector // Dedicated injector for this attack
}

// AuthFloodEngine manages multiple concurrent auth flood attacks
type AuthFloodEngine struct {
	injector      *injection.Injector
	activeAttacks map[string]*AuthFloodController
	mu            sync.RWMutex
	maxConcurrent int
	locker        capture.ChannelLocker
	logger        func(string, string)
}

// NewAuthFloodEngine creates a new auth flood engine
func NewAuthFloodEngine(injector *injection.Injector, locker capture.ChannelLocker, maxConcurrent int) *AuthFloodEngine {
	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}
	return &AuthFloodEngine{
		injector:      injector,
		activeAttacks: make(map[string]*AuthFloodController),
		maxConcurrent: maxConcurrent,
		locker:        locker,
	}
}

// SetLogger sets the callback for logging events
func (e *AuthFloodEngine) SetLogger(logger func(string, string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logger = logger
}

// log sends a message to the logger callback asynchronously
func (e *AuthFloodEngine) log(message string, level string) {
	e.mu.RLock()
	logger := e.logger
	e.mu.RUnlock()

	if logger != nil {
		go logger(message, level)
	}
}

// validateConfig validates the attack configuration
func (e *AuthFloodEngine) validateConfig(config domain.AuthFloodAttackConfig) error {
	if config.TargetBSSID == "" {
		return ErrTargetBSSIDRequired
	}

	if config.AttackType == "assoc" && config.TargetSSID == "" {
		return ErrTargetSSIDRequired
	}

	return nil
}

// prepareInjector selects or creates an injector for the attack
// Returns: (attackInjector, dedicatedInjector, error)
func (e *AuthFloodEngine) prepareInjector(config *domain.AuthFloodAttackConfig) (*injection.Injector, *injection.Injector, error) {
	// Set default interface if not specified
	if config.Interface == "" && e.injector != nil {
		config.Interface = e.injector.Interface
	}

	// Use default injector if no specific interface requested
	if config.Interface == "" {
		return e.injector, nil, nil
	}

	// Reuse default injector if it matches the requested interface
	if e.injector != nil && e.injector.Interface == config.Interface {
		return e.injector, nil, nil
	}

	// Set channel if specified
	if config.Channel > 0 {
		if err := driver.SetInterfaceChannel(config.Interface, config.Channel); err != nil {
			e.log(fmt.Sprintf("Warning: Failed to set channel %d on %s: %v", config.Channel, config.Interface, err), "warning")
		}
	}

	// Create dedicated injector for this interface
	inj, err := injection.NewInjector(config.Interface)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create injector for interface %s: %w", config.Interface, err)
	}

	return inj, inj, nil
}

// checkConcurrentLimit checks if we can start a new attack
func (e *AuthFloodEngine) checkConcurrentLimit() error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.activeAttacks) >= e.maxConcurrent {
		return fmt.Errorf("%w (%d)", ErrMaxConcurrentReached, e.maxConcurrent)
	}

	return nil
}

// registerAttack adds a new attack controller to the active attacks map
func (e *AuthFloodEngine) registerAttack(controller *AuthFloodController) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeAttacks[controller.ID] = controller
}

// StartAttack initiates a new auth flood attack
func (e *AuthFloodEngine) StartAttack(ctx context.Context, config domain.AuthFloodAttackConfig) (string, error) {
	// Cleanup finished attacks first
	e.CleanupFinished()

	// Validate configuration
	if err := e.validateConfig(config); err != nil {
		return "", err
	}

	// Check concurrent limit
	if err := e.checkConcurrentLimit(); err != nil {
		return "", err
	}

	// Prepare injector
	attackInjector, dedicatedInjector, err := e.prepareInjector(&config)
	if err != nil {
		return "", err
	}

	// Create attack context and controller
	attackID := uuid.New().String()
	attackCtx, cancel := context.WithCancel(ctx)
	statusCh := make(chan domain.AuthFloodAttackStatus, 10)

	controller := &AuthFloodController{
		ID:       attackID,
		Config:   config,
		CancelFn: cancel,
		StatusCh: statusCh,
		injector: dedicatedInjector,
		Status: domain.AuthFloodAttackStatus{
			ID:          attackID,
			Config:      config,
			Status:      domain.AttackPending,
			PacketsSent: 0,
			StartTime:   time.Now(),
		},
	}

	// Register attack
	e.registerAttack(controller)

	// Start attack execution
	go e.runAttack(attackCtx, controller, attackInjector)

	e.log(fmt.Sprintf("Started Auth Flood %s against %s", attackID, config.TargetBSSID), "success")

	return attackID, nil
}

// setupStatusConsumer starts a goroutine to consume status updates
func (e *AuthFloodEngine) setupStatusConsumer(controller *AuthFloodController) {
	go func() {
		for status := range controller.StatusCh {
			controller.mu.Lock()
			controller.Status.Status = status.Status
			controller.Status.PacketsSent = status.PacketsSent
			controller.mu.Unlock()
		}
	}()
}

// cleanupAttackResources ensures all attack resources are properly cleaned up
func (e *AuthFloodEngine) cleanupAttackResources(controller *AuthFloodController) {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	if controller.injector != nil {
		controller.injector.Close()
		controller.injector = nil
	}
}

// handleAttackPanic recovers from panics and updates attack status
func (e *AuthFloodEngine) handleAttackPanic(controller *AuthFloodController) {
	if r := recover(); r != nil {
		e.log(fmt.Sprintf("Attack %s panicked: %v", controller.ID, r), "danger")

		controller.mu.Lock()
		controller.Status.Status = domain.AttackFailed
		controller.Status.ErrorMessage = fmt.Sprintf("panic: %v", r)
		now := time.Now()
		controller.Status.EndTime = &now
		controller.mu.Unlock()
	}
}

// executeAttack performs the actual attack execution
func (e *AuthFloodEngine) executeAttack(ctx context.Context, controller *AuthFloodController, injector *injection.Injector) error {
	if injector == nil {
		return ErrNoInjectorAvailable
	}

	// Update status to running
	controller.mu.Lock()
	controller.Status.Status = domain.AttackRunning
	controller.mu.Unlock()

	// Setup status consumer
	e.setupStatusConsumer(controller)

	// Execute attack (blocking)
	err := injector.StartAuthFlood(ctx, controller.Config, controller.StatusCh)

	// Close status channel to stop consumer
	close(controller.StatusCh)

	return err
}

// runAttack executes the attack logic with proper resource management
func (e *AuthFloodEngine) runAttack(ctx context.Context, controller *AuthFloodController, injector *injection.Injector) {
	// Ensure cleanup and panic recovery
	defer e.cleanupAttackResources(controller)
	defer e.handleAttackPanic(controller)

	// Define attack action
	action := func() error {
		return e.executeAttack(ctx, controller, injector)
	}

	// Execute with or without channel lock
	var err error
	if e.locker != nil && controller.Config.Channel > 0 {
		err = e.locker.ExecuteWithLock(ctx, controller.Config.Interface, controller.Config.Channel, action)
	} else {
		err = action()
	}

	// Update final status
	e.updateFinalStatus(controller, err)
}

// updateFinalStatus updates the attack status after completion
func (e *AuthFloodEngine) updateFinalStatus(controller *AuthFloodController, err error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	now := time.Now()

	if err != nil {
		e.log(fmt.Sprintf("Auth Flood %s failed: %v", controller.ID, err), "error")
		controller.Status.Status = domain.AttackFailed
		controller.Status.ErrorMessage = err.Error()
	} else {
		if controller.Status.Status == domain.AttackRunning {
			controller.Status.Status = domain.AttackStopped
		}
		e.log(fmt.Sprintf("Auth Flood %s completed", controller.ID), "info")
	}

	controller.Status.EndTime = &now
}

// StopAttack stops a running attack
func (e *AuthFloodEngine) StopAttack(ctx context.Context, id string, force bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("%w: %s", ErrAttackNotFound, id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if !force && controller.Status.Status != domain.AttackRunning && controller.Status.Status != domain.AttackPaused {
		return fmt.Errorf("%w: %s", ErrAttackNotActive, id)
	}

	// Cancel context
	controller.CancelFn()

	// Close dedicated injector if exists
	if controller.injector != nil {
		controller.injector.Close()
		controller.injector = nil
	}

	// Update status
	controller.Status.Status = domain.AttackStopped
	now := time.Now()
	controller.Status.EndTime = &now
	if force {
		controller.Status.ErrorMessage = "Force stopped by user"
	}

	e.log(fmt.Sprintf("Stopped Auth Flood %s", id), "warning")
	return nil
}

// GetStatus returns the current status of an attack
func (e *AuthFloodEngine) GetStatus(ctx context.Context, id string) (domain.AuthFloodAttackStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return domain.AuthFloodAttackStatus{}, fmt.Errorf("%w: %s", ErrAttackNotFound, id)
	}

	controller.mu.RLock()
	defer controller.mu.RUnlock()
	return controller.Status, nil
}

// CleanupFinished removes finished attacks from the active list
func (e *AuthFloodEngine) CleanupFinished() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for id, controller := range e.activeAttacks {
		controller.mu.RLock()
		finished := controller.Status.Status == domain.AttackStopped || controller.Status.Status == domain.AttackFailed
		controller.mu.RUnlock()

		if finished {
			delete(e.activeAttacks, id)
		}
	}
}

// StopAll stops all active attacks
func (e *AuthFloodEngine) StopAll(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, controller := range e.activeAttacks {
		controller.CancelFn()

		controller.mu.Lock()
		if controller.injector != nil {
			controller.injector.Close()
			controller.injector = nil
		}

		if controller.Status.Status == domain.AttackRunning {
			controller.Status.Status = domain.AttackStopped
			now := time.Now()
			controller.Status.EndTime = &now
			controller.Status.ErrorMessage = "Service shutdown"
		}
		controller.mu.Unlock()
	}
}
