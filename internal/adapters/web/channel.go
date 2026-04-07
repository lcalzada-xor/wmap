package handlers

import (
	"encoding/json"
	"net/http"
)

// HandleGetChannels returns available channels
func (api *API) HandleGetChannels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	iface := r.URL.Query().Get("interface")
	var channels []int
	var err error

	if iface != "" {
		channels, err = api.Scanner.GetInterfaceChannels(ctx, iface)
	} else {
		// Fallback or Global
		channels, err = api.Scanner.GetChannels(ctx)
	}

	if err != nil {
		RespondError(w, http.StatusInternalServerError, "Failed to get channels: "+err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, map[string]interface{}{"channels": channels})
}

// HandleUpdateChannels updates channel list
func (api *API) HandleUpdateChannels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Interface string `json:"interface"`
		Channels  []int  `json:"channels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var err error
	if req.Interface != "" {
		err = api.Scanner.SetInterfaceChannels(ctx, req.Interface, req.Channels)
	} else {
		err = api.Scanner.SetChannels(ctx, req.Channels)
	}

	if err != nil {
		RespondError(w, http.StatusInternalServerError, "Failed to set channels: "+err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, map[string]string{"status": "channels_updated"})
}
