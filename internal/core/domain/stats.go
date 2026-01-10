package domain

type SystemStats struct {
	DeviceCount   int            `json:"device_count"`
	AlertCount    int            `json:"alert_count"`
	VendorStats   map[string]int `json:"vendor_stats"`
	SecurityStats map[string]int `json:"security_stats"` // WPA2, WPA3, OPEN...
	GlobalRetry   float64        `json:"global_retry"`   // Avg retry rate
}
