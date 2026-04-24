package web

import "net/http"

// HandleGetStats returns system intelligence stats
func (api *API) HandleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := api.Scanner.GetSystemStats(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "Failed to get stats: "+err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, stats)
}
