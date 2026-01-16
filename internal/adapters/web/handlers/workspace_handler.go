package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/workspace"
)

// WorkspaceHandler handles workspace operations
type WorkspaceHandler struct {
	Service          ports.NetworkService
	WorkspaceManager *workspace.WorkspaceManager
}

// NewWorkspaceHandler creates a new WorkspaceHandler
func NewWorkspaceHandler(service ports.NetworkService, workspaceManager *workspace.WorkspaceManager) *WorkspaceHandler {
	return &WorkspaceHandler{
		Service:          service,
		WorkspaceManager: workspaceManager,
	}
}

// HandleListWorkspaces returns list of available workspaces
func (h *WorkspaceHandler) HandleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	workspaces, err := h.WorkspaceManager.ListWorkspaces()
	if err != nil {
		http.Error(w, "Failed to list workspaces", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"workspaces": workspaces})
}

// HandleCreateWorkspace creates a new workspace
func (h *WorkspaceHandler) HandleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	if err := h.WorkspaceManager.CreateWorkspace(req.Name); err != nil {
		http.Error(w, "Failed to create workspace: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"created"}`))
}

// HandleLoadWorkspace loads a specific workspace
func (h *WorkspaceHandler) HandleLoadWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	if err := h.WorkspaceManager.LoadWorkspace(req.Name); err != nil {
		http.Error(w, "Failed to load workspace: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"loaded"}`))
}

// HandleStatus returns current workspace status
func (h *WorkspaceHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	current := h.WorkspaceManager.GetCurrentWorkspace()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"currentWorkspace": current,
	})
}

// HandleClear clears the current workspace data
func (h *WorkspaceHandler) HandleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.Service.ResetWorkspace()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"workspace_cleared"}`))
}
