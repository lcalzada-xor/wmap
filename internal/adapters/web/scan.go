package web

import "net/http"

// HandleScan triggers an active scan
func (api *API) HandleScan(w http.ResponseWriter, r *http.Request) {
	err := api.Scanner.TriggerScan(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "Scan failed: "+err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, map[string]string{"status": "scan_initiated"})
}
