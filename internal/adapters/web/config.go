package web

import "net/http"

// HandleGetConfig returns current configuration
func (api *API) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"persistenceEnabled": api.Config.IsPersistenceEnabled(),
	}
	RespondJSON(w, http.StatusOK, config)
}

// HandleTogglePersistence toggles data persistence
func (api *API) HandleTogglePersistence(w http.ResponseWriter, r *http.Request) {
	enabledStr := r.URL.Query().Get("enabled")
	enabled := enabledStr == "true"
	api.Config.SetPersistenceEnabled(enabled)

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "persistence_updated",
		"enabled": enabled,
	})
}
