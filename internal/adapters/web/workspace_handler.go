package web

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	workspaces, err := s.WorkspaceManager.ListWorkspaces()
	if err != nil {
		http.Error(w, "Failed to list workspaces", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"workspaces": workspaces})
}

func (s *Server) handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
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
	if err := s.WorkspaceManager.CreateWorkspace(req.Name); err != nil {
		http.Error(w, "Failed to create workspace: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"created"}`))
}

func (s *Server) handleLoadWorkspace(w http.ResponseWriter, r *http.Request) {
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
	if err := s.WorkspaceManager.LoadWorkspace(req.Name); err != nil {
		http.Error(w, "Failed to load workspace: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"loaded"}`))
}

func (s *Server) handleWorkspaceStatus(w http.ResponseWriter, r *http.Request) {
	current := s.WorkspaceManager.GetCurrentWorkspace()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"currentWorkspace": current,
	})
}

func (s *Server) handleWorkspaceClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.Service.ResetWorkspace()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"workspace_cleared"}`))
}
