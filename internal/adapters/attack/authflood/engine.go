package authflood

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
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
	Logger        func(string, string)
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
	e.Logger = logger
}

func (e *AuthFloodEngine) log(message string, level string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.Logger != nil {
		go e.Logger(message, level)
	}
}

// StartAttack initiates a new auth flood attack
func (e *AuthFloodEngine) StartAttack(config domain.AuthFloodAttackConfig) (string, error) {
	e.CleanupFinished()

	e.mu.Lock()
	if len(e.activeAttacks) >= e.maxConcurrent {
		e.mu.Unlock()
		return "", fmt.Errorf("maximum concurrent attacks (%d) reached", e.maxConcurrent)
	}
	e.mu.Unlock()

	if config.TargetBSSID == "" {
		return "", fmt.Errorf("target BSSID is required")
	}

	attackID := uuid.New().String()

	// Interface & injection.Injector Selection
	if config.Interface == "" && e.injector != nil {
		config.Interface = e.injector.Interface
	}

	var attackInjector *injection.Injector = e.injector
	var dedicatedInjector *injection.Injector = nil

	if config.Interface != "" {
		if e.injector != nil && e.injector.Interface == config.Interface {
			attackInjector = e.injector
		} else {
			// Enforce Channel if provided
			if config.Channel > 0 {
				if err := driver.SetInterfaceChannel(config.Interface, config.Channel); err != nil {
					e.log(fmt.Sprintf("Warning: Failed to set channel %d on %s: %v", config.Channel, config.Interface, err), "warning")
				}
			}

			inj, err := injection.NewInjector(config.Interface)
			if err != nil {
				return "", fmt.Errorf("failed to create injector for interface %s: %w", config.Interface, err)
			}
			attackInjector = inj
			dedicatedInjector = inj
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
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

	e.mu.Lock()
	e.activeAttacks[attackID] = controller
	e.mu.Unlock()

	go e.runAttack(ctx, controller, attackInjector)

	e.log(fmt.Sprintf("Started Auth Flood %s against %s", attackID, config.TargetBSSID), "success")

	return attackID, nil
}

func (e *AuthFloodEngine) runAttack(ctx context.Context, controller *AuthFloodController, injector *injection.Injector) {
	action := func() error {
		defer func() {
			controller.mu.Lock()
			if controller.injector != nil {
				controller.injector.Close()
			}
			controller.mu.Unlock()

			if r := recover(); r != nil {
				e.log(fmt.Sprintf("Attack %s panicked: %v", controller.ID, r), "danger")
				controller.mu.Lock()
				controller.Status.Status = domain.AttackFailed
				controller.Status.ErrorMessage = fmt.Sprintf("panic: %v", r)
				now := time.Now()
				controller.Status.EndTime = &now
				controller.mu.Unlock()
			}
		}()

		controller.mu.Lock()
		controller.Status.Status = domain.AttackRunning
		controller.mu.Unlock()

		if injector == nil {
			return fmt.Errorf("no injector available")
		}

		// Start Status Consumer
		go func() {
			for status := range controller.StatusCh {
				controller.mu.Lock()
				controller.Status.Status = status.Status
				controller.Status.PacketsSent = status.PacketsSent
				controller.mu.Unlock()
			}
		}()

		// Use the new StartAuthFlood method (Blocking)
		err := injector.StartAuthFlood(ctx, controller.Config, controller.StatusCh)

		// Close channel to stop consumer
		close(controller.StatusCh)

		return err
	}

	var err error
	if e.locker != nil && controller.Config.Channel > 0 {
		err = e.locker.ExecuteWithLock(ctx, controller.Config.Interface, controller.Config.Channel, action)
	} else {
		err = action()
	}

	if err != nil {
		e.log(fmt.Sprintf("Available Flood %s failed: %v", controller.ID, err), "error")
		controller.mu.Lock()
		controller.Status.Status = domain.AttackFailed
		controller.Status.ErrorMessage = err.Error()
		controller.mu.Unlock()
	} else {
		controller.mu.Lock()
		if controller.Status.Status == domain.AttackRunning {
			controller.Status.Status = domain.AttackStopped
		}
		now := time.Now()
		controller.Status.EndTime = &now
		controller.mu.Unlock()
		e.log(fmt.Sprintf("Auth Flood %s completed", controller.ID), "info")
	}
}

func (e *AuthFloodEngine) StopAttack(id string, force bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("attack %s not found", id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if !force && controller.Status.Status != domain.AttackRunning && controller.Status.Status != domain.AttackPaused {
		return fmt.Errorf("attack %s is not active", id)
	}

	controller.CancelFn()
	if controller.injector != nil {
		controller.injector.Close()
	}

	controller.Status.Status = domain.AttackStopped
	now := time.Now()
	controller.Status.EndTime = &now
	if force {
		controller.Status.ErrorMessage = "Force stopped by user"
	}

	e.log(fmt.Sprintf("Stopped Auth Flood %s", id), "warning")
	return nil
}

func (e *AuthFloodEngine) GetStatus(id string) (domain.AuthFloodAttackStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return domain.AuthFloodAttackStatus{}, fmt.Errorf("attack %s not found", id)
	}

	controller.mu.RLock()
	defer controller.mu.RUnlock()
	return controller.Status, nil
}

func (e *AuthFloodEngine) CleanupFinished() {
	e.mu.Lock()
	for id, controller := range e.activeAttacks {
		controller.mu.RLock()
		finished := controller.Status.Status == domain.AttackStopped || controller.Status.Status == domain.AttackFailed
		controller.mu.RUnlock()
		if finished {
			delete(e.activeAttacks, id)
		}
	}
	e.mu.Unlock()
}

// StopAll stops all active attacks.
func (e *AuthFloodEngine) StopAll() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, controller := range e.activeAttacks {
		controller.CancelFn()
		if controller.injector != nil {
			controller.injector.Close()
		}
		// Update status
		controller.mu.Lock()
		if controller.Status.Status == domain.AttackRunning {
			controller.Status.Status = domain.AttackStopped
			now := time.Now()
			controller.Status.EndTime = &now
			controller.Status.ErrorMessage = "Service shutdown"
		}
		controller.mu.Unlock()
	}
	// Clear map logic? No, just stop them. CleanupFinished will remove them.
}
