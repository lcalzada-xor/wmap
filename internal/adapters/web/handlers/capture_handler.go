package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type CaptureHandler struct {
	// We might need dependencies later, e.g. config
}

func NewCaptureHandler() *CaptureHandler {
	return &CaptureHandler{}
}

// OpenHandshakeFolderRequest
type OpenHandshakeFolderRequest struct {
	MAC string `json:"mac"`
}

// HandleOpenHandshakeFolder opens the file explorer at the handshake directory
func (h *CaptureHandler) HandleOpenHandshakeFolder(w http.ResponseWriter, r *http.Request) {
	var req OpenHandshakeFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Resolve Path (replicated from manager.go for now, ideally strictly configured)
	home, err := os.UserHomeDir()
	if err != nil {
		http.Error(w, "Could not resolve home directory", http.StatusInternalServerError)
		return
	}
	handshakeDir := filepath.Join(home, ".local", "share", "wmap", "handshakes")

	// Ensure it exists
	if _, err := os.Stat(handshakeDir); os.IsNotExist(err) {
		http.Error(w, "Handshake directory does not exist", http.StatusNotFound)
		return
	}

	log.Printf("Opening handshake folder: %s", handshakeDir)

	// Execute open command based on OS
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", handshakeDir)
	case "darwin":
		cmd = exec.Command("open", handshakeDir)
	case "windows":
		cmd = exec.Command("explorer", handshakeDir)
	default:
		http.Error(w, "Unsupported OS", http.StatusNotImplemented)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("Error opening folder: %v", err)
		http.Error(w, fmt.Sprintf("Failed to open folder: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "opened", "path": handshakeDir})
}
