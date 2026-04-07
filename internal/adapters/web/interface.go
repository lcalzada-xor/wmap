package handlers

import "net/http"

// HandleListInterfaces returns list of network interfaces
func (api *API) HandleListInterfaces(w http.ResponseWriter, r *http.Request) {
	details, err := api.Scanner.GetInterfaceDetails(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "Failed to list interfaces: "+err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, map[string]interface{}{"interfaces": details})
}
