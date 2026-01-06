package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/adapters/storage"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// SessionManager handles the lifecycle of user sessions (database files).
type SessionManager struct {
	baseDir        string
	currentSession string
	currentStorage ports.Storage

	persistence *PersistenceManager
	registry    ports.DeviceRegistry

	mu sync.RWMutex
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(baseDir string, persistence *PersistenceManager, registry ports.DeviceRegistry) (*SessionManager, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	return &SessionManager{
		baseDir:     baseDir,
		persistence: persistence,
		registry:    registry,
	}, nil
}

// ListSessions returns a list of available session names.
func (s *SessionManager) ListSessions() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	files, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, err
	}

	var sessions []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".db") {
			name := strings.TrimSuffix(f.Name(), ".db")
			sessions = append(sessions, name)
		}
	}
	return sessions, nil
}

// GetCurrentSession returns the name of the currently active session.
func (s *SessionManager) GetCurrentSession() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentSession
}

// CreateSession creates a new session database and loads it.
func (s *SessionManager) CreateSession(name string) error {
	// Validate name (basic)
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid session name")
	}

	path := filepath.Join(s.baseDir, name+".db")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("session '%s' already exists", name)
	}

	// Just load it, LoadSession will handle creation via SQLite adapter if not strictly checking
	// But let's be explicit: The adapter creates the file if missing.
	return s.LoadSession(name)
}

// LoadSession switches the active session to the specified one.
func (s *SessionManager) LoadSession(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate name
	if name == "" {
		return fmt.Errorf("session name cannot be empty")
	}

	path := filepath.Join(s.baseDir, name+".db")

	// Initialize new storage
	newStore, err := storage.NewSQLiteAdapter(path)
	if err != nil {
		return fmt.Errorf("failed to open session storage: %w", err)
	}

	// Close old storage
	if s.currentStorage != nil {
		if err := s.currentStorage.Close(); err != nil {
			fmt.Printf("Warning: failed to close previous storage: %v\n", err)
		}
	}

	// Switch refs
	s.currentStorage = newStore
	s.currentSession = name

	// Update Persistence Manager
	if s.persistence != nil {
		s.persistence.SetStorage(newStore)
	}

	// Repopulate Registry
	// 1. Clear current in-memory state
	s.registry.Clear()

	// 2. Load from DB
	devices, err := newStore.GetAllDevices()
	if err != nil {
		return fmt.Errorf("accessed DB but failed to read devices: %w", err)
	}

	// 3. Hydrate Registry
	for _, d := range devices {
		// We use ProcessDevice to hydrate.
		// Note: ProcessDevice might trigger persistence again?
		// Registry.ProcessDevice updates memory.
		// NetworkService.ProcessDevice does registry + security + persistence.
		// We should ONLY call registry.ProcessDevice here to avoid infinite loops or re-analyzing old data unnecessarily.
		s.registry.ProcessDevice(d)
	}

	return nil
}

// Close closes the current session.
func (s *SessionManager) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentStorage != nil {
		return s.currentStorage.Close()
	}
	return nil
}
