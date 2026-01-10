package web

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"persistenceEnabled": s.Service.IsPersistenceEnabled(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (s *Server) handleTogglePersistence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enabledStr := r.URL.Query().Get("enabled")
	enabled := enabledStr == "true"
	s.Service.SetPersistenceEnabled(enabled)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"persistence_updated","enabled":%v}`, enabled)
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		iface := r.URL.Query().Get("interface")
		var channels []int
		if iface != "" {
			channels = s.Service.GetInterfaceChannels(iface)
		} else {
			// Fallback or Global
			channels = s.Service.GetChannels()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"channels": channels,
		})
	case http.MethodPost:
		// Update channel list
		var req struct {
			Interface string `json:"interface"`
			Channels  []int  `json:"channels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Interface != "" {
			s.Service.SetInterfaceChannels(req.Interface, req.Channels)
		} else {
			s.Service.SetChannels(req.Channels)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"channels_updated"}`))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleListInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Use new detailed method
	details := s.Service.GetInterfaceDetails()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interfaces": details,
	})
}
