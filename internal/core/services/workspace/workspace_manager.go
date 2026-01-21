package workspace

import (
"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/adapters/storage"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
)

// WorkspaceManager handles the lifecycle of user workspaces (database files).
type WorkspaceManager struct {
	baseDir          string
	currentWorkspace string
	currentStorage   ports.Storage

	persistence *persistence.PersistenceManager
	registry    ports.DeviceRegistry

	mu sync.RWMutex
}

// NewWorkspaceManager creates a new WorkspaceManager.
func NewWorkspaceManager(baseDir string, persistence *persistence.PersistenceManager, registry ports.DeviceRegistry) (*WorkspaceManager, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace directory: %w", err)
	}

	return &WorkspaceManager{
		baseDir:     baseDir,
		persistence: persistence,
		registry:    registry,
	}, nil
}

// ListWorkspaces returns a list of available workspace names.
func (s *WorkspaceManager) ListWorkspaces() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	files, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, err
	}

	var workspaces []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".db") {
			name := strings.TrimSuffix(f.Name(), ".db")
			workspaces = append(workspaces, name)
		}
	}
	return workspaces, nil
}

// GetCurrentWorkspace returns the name of the currently active workspace.
func (s *WorkspaceManager) GetCurrentWorkspace() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentWorkspace
}

// CreateWorkspace creates a new workspace database and loads it.
func (s *WorkspaceManager) CreateWorkspace(name string) error {
	// Validate name (basic)
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid workspace name")
	}

	path := filepath.Join(s.baseDir, name+".db")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("workspace '%s' already exists", name)
	}

	// Just load it, LoadWorkspace will handle creation via SQLite adapter if not strictly checking
	// But let's be explicit: The adapter creates the file if missing.
	return s.LoadWorkspace(name)
}

// LoadWorkspace switches the active workspace to the specified one.
func (s *WorkspaceManager) LoadWorkspace(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate name
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid workspace name")
	}

	path := filepath.Join(s.baseDir, name+".db")

	// Initialize new storage
	newStore, err := storage.NewSQLiteAdapter(path)
	if err != nil {
		return fmt.Errorf("failed to open workspace storage: %w", err)
	}

	// Close old storage
	if s.currentStorage != nil {
		if err := s.currentStorage.Close(); err != nil {
			fmt.Printf("Warning: failed to close previous storage: %v\n", err)
		}
	}

	// Switch refs
	s.currentStorage = newStore
	s.currentWorkspace = name

	// Update Persistence Manager
	if s.persistence != nil {
		s.persistence.SetStorage(newStore)
	}

	// Repopulate Registry
	// 1. Clear current in-memory state
	s.registry.Clear(context.Background())

	// 2. Load from DB
	devices, err := newStore.GetAllDevices(context.Background())
	if err != nil {
		return fmt.Errorf("accessed DB but failed to read devices: %w", err)
	}

	// 3. Hydrate Registry
	for _, d := range devices {
		// We use LoadDevice to restore state without resetting timestamps.
		s.registry.LoadDevice(context.Background(), d)
	}

	return nil
}

// DeleteWorkspace deletes a workspace database file.
func (s *WorkspaceManager) DeleteWorkspace(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate name
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid workspace name")
	}

	// Prevent deleting the active workspace
	if name == s.currentWorkspace {
		return fmt.Errorf("cannot delete the currently active workspace")
	}

	path := filepath.Join(s.baseDir, name+".db")

	// Check if exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("workspace not found")
	}

	// Delete file
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete workspace: %w", err)
	}

	return nil
}

// Close closes the current workspace.
func (s *WorkspaceManager) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentStorage != nil {
		return s.currentStorage.Close()
	}
	return nil
}
