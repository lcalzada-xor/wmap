package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// MockStorage implements ports.Storage for testing
type MockStorage struct {
	vulnerabilities []domain.VulnerabilityRecord
}

func (m *MockStorage) SaveDevice(ctx context.Context, device domain.Device) error {
	return nil
}

func (m *MockStorage) SaveDevicesBatch(ctx context.Context, devices []domain.Device) error {
	return nil
}

func (m *MockStorage) GetDevice(ctx context.Context, mac string) (*domain.Device, error) {
	return nil, nil
}

func (m *MockStorage) GetAllDevices(ctx context.Context) ([]domain.Device, error) {
	return []domain.Device{}, nil
}

func (m *MockStorage) SaveProbe(ctx context.Context, mac string, ssid string) error {
	return nil
}

func (m *MockStorage) SaveVulnerability(ctx context.Context, record domain.VulnerabilityRecord) error {
	return nil
}

func (m *MockStorage) GetVulnerabilities(ctx context.Context, filter domain.VulnerabilityFilter) ([]domain.VulnerabilityRecord, error) {
	return m.vulnerabilities, nil
}

func (m *MockStorage) GetVulnerability(ctx context.Context, id string) (*domain.VulnerabilityRecord, error) {
	return nil, nil
}

func (m *MockStorage) UpdateVulnerabilityStatus(ctx context.Context, id string, status domain.VulnerabilityStatus, notes string) error {
	return nil
}

func (m *MockStorage) Close() error {
	return nil
}

// MockDeviceRegistry implements ports.DeviceRegistry for testing
type MockDeviceRegistry struct{}

func (m *MockDeviceRegistry) ProcessDevice(ctx context.Context, device domain.Device) (domain.Device, bool) {
	return device, false
}

func (m *MockDeviceRegistry) LoadDevice(ctx context.Context, device domain.Device) {
}

func (m *MockDeviceRegistry) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	return domain.Device{}, false
}

func (m *MockDeviceRegistry) GetAllDevices(ctx context.Context) []domain.Device {
	return []domain.Device{}
}

func (m *MockDeviceRegistry) PruneOldDevices(ctx context.Context, ttl time.Duration) int {
	return 0
}

func (m *MockDeviceRegistry) CleanupStaleConnections(ctx context.Context, timeout time.Duration) int {
	return 0
}

func (m *MockDeviceRegistry) GetActiveCount(ctx context.Context) int {
	return 0
}

func (m *MockDeviceRegistry) UpdateSSID(ctx context.Context, ssid, security string) {
}

func (m *MockDeviceRegistry) GetSSIDs(ctx context.Context) map[string]bool {
	return make(map[string]bool)
}

func (m *MockDeviceRegistry) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	return "", false
}

func (m *MockDeviceRegistry) Clear(ctx context.Context) {
}

func TestExecutiveReportGeneratorGenerate(t *testing.T) {
	// Create mock storage with test data
	mockStorage := &MockStorage{
		vulnerabilities: []domain.VulnerabilityRecord{
			{
				Name:       "WPS-PIXIE",
				Severity:   domain.Severity(9),
				Confidence: domain.Confidence(1.0),
				Status:     domain.VulnStatusActive,
				DeviceMAC:  "aa:bb:cc:dd:ee:01",
				FirstSeen:  time.Now().AddDate(0, 0, -5),
			},
			{
				Name:       "WPS-PIXIE",
				Severity:   domain.Severity(9),
				Confidence: domain.Confidence(1.0),
				Status:     domain.VulnStatusActive,
				DeviceMAC:  "aa:bb:cc:dd:ee:02",
				FirstSeen:  time.Now().AddDate(0, 0, -5),
			},
			{
				Name:       "OPEN-NETWORK",
				Severity:   domain.Severity(8),
				Confidence: domain.Confidence(1.0),
				Status:     domain.VulnStatusActive,
				DeviceMAC:  "aa:bb:cc:dd:ee:03",
				FirstSeen:  time.Now().AddDate(0, 0, -3),
			},
			{
				Name:       "DEFAULT-SSID",
				Severity:   domain.Severity(5),
				Confidence: domain.Confidence(0.8),
				Status:     domain.VulnStatusActive,
				DeviceMAC:  "aa:bb:cc:dd:ee:04",
				FirstSeen:  time.Now().AddDate(0, 0, -2),
			},
			{
				Name:       "PROBE-LEAKAGE",
				Severity:   domain.Severity(4),
				Confidence: domain.Confidence(0.7),
				Status:     domain.VulnStatusActive,
				DeviceMAC:  "aa:bb:cc:dd:ee:05",
				FirstSeen:  time.Now().AddDate(0, 0, -1),
			},
		},
	}

	mockRegistry := &MockDeviceRegistry{}

	generator := NewExecutiveReportGenerator(mockStorage, mockRegistry)

	// Test report generation
	dateRange := domain.DateRange{
		Start: time.Now().AddDate(0, 0, -30),
		End:   time.Now(),
	}

	report, err := generator.Generate(context.Background(), dateRange, "Test Organization")

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify metadata
	if report.Metadata.Type != domain.ReportTypeExecutive {
		t.Errorf("Report type = %v, want %v", report.Metadata.Type, domain.ReportTypeExecutive)
	}

	if report.Metadata.OrganizationName != "Test Organization" {
		t.Errorf("Organization name = %v, want Test Organization", report.Metadata.OrganizationName)
	}

	if report.Metadata.ID == "" {
		t.Error("Report ID is empty")
	}

	// Verify device count
	if report.TotalDevices != 5 {
		t.Errorf("Total devices = %d, want 5", report.TotalDevices)
	}

	// Verify statistics
	if report.VulnStats.Total != 5 {
		t.Errorf("Total vulnerabilities = %d, want 5", report.VulnStats.Total)
	}

	if report.VulnStats.Critical < 1 {
		t.Error("Should have at least 1 critical vulnerability")
	}

	if report.VulnStats.Confirmed < 1 {
		t.Error("Should have at least 1 confirmed vulnerability")
	}

	// Verify risk score
	if report.RiskScore < 0 || report.RiskScore > 10 {
		t.Errorf("Risk score %v out of range [0, 10]", report.RiskScore)
	}

	// Verify risk level
	validLevels := map[string]bool{"Low": true, "Medium": true, "High": true, "Critical": true}
	if !validLevels[report.RiskLevel] {
		t.Errorf("Invalid risk level: %v", report.RiskLevel)
	}

	// Verify top risks
	if len(report.TopRisks) == 0 {
		t.Error("Top risks is empty")
	}

	if len(report.TopRisks) > 5 {
		t.Errorf("Top risks should be limited to 5, got %d", len(report.TopRisks))
	}

	// Verify recommendations
	if len(report.Recommendations) == 0 {
		t.Error("Recommendations is empty")
	}

	if len(report.Recommendations) > 5 {
		t.Errorf("Recommendations should be limited to 5, got %d", len(report.Recommendations))
	}
}

func TestCalculateStats(t *testing.T) {
	generator := &ExecutiveReportGenerator{}

	vulns := []domain.VulnerabilityRecord{
		{Name: "WPS-PIXIE", Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive},
		{Name: "OPEN-NETWORK", Severity: domain.Severity(9), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive},
		{Name: "DEFAULT-SSID", Severity: domain.Severity(7), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive},
		{Name: "PROBE-LEAKAGE", Severity: domain.Severity(5), Confidence: domain.Confidence(0.7), Status: domain.VulnStatusActive},
		{Name: "TKIP-ONLY", Severity: domain.Severity(4), Confidence: domain.Confidence(0.6), Status: domain.VulnStatusFixed},
		{Name: "WEP", Severity: domain.Severity(3), Confidence: domain.Confidence(0.5), Status: domain.VulnStatusIgnored},
	}

	stats := generator.calculateStats(vulns)

	// Verify total
	if stats.Total != 6 {
		t.Errorf("Total = %d, want 6", stats.Total)
	}

	// Verify severity counts
	if stats.Critical < 1 {
		t.Error("Should have at least 1 critical (severity >= 9)")
	}

	if stats.High < 1 {
		t.Error("Should have at least 1 high (severity >= 7)")
	}

	// Verify status counts
	if stats.ByStatus["active"] < 1 {
		t.Error("Should have active vulnerabilities")
	}

	if stats.ByStatus["fixed"] < 1 {
		t.Error("Should have fixed vulnerabilities")
	}

	// Verify confidence counts
	if stats.Confirmed < 1 {
		t.Error("Should have confirmed vulnerabilities (confidence = 1.0)")
	}

	if stats.Unconfirmed < 1 {
		t.Error("Should have unconfirmed vulnerabilities (confidence < 1.0)")
	}

	// Verify category counts
	if len(stats.ByCategory) == 0 {
		t.Error("ByCategory should not be empty")
	}
}

func TestInferCategory(t *testing.T) {
	generator := &ExecutiveReportGenerator{}

	tests := []struct {
		vulnName string
		expected string
	}{
		{"WEP", "Protocol Weakness"},
		{"TKIP", "Protocol Weakness"},
		{"KRACK", "Protocol Weakness"},
		{"WEAK-WPA", "Protocol Weakness"},
		{"DRAGONBLOOD", "Protocol Weakness"},
		{"NO-PMF", "Protocol Weakness"},
		{"WPS-PIXIE", "Configuration"},
		{"OPEN-NETWORK", "Configuration"},
		{"DEFAULT-SSID", "Configuration"},
		{"FT-PSK", "Configuration"},
		{"FT-OVER-DS", "Configuration"},
		{"PROBE-LEAKAGE", "Client Security"},
		{"MAC-RAND-FAIL", "Client Security"},
		{"LEGACY-WEP-SUPPORT", "Client Security"},
		{"PMKID-EXPOSURE", "Attack Surface"},
		{"PMKID", "Attack Surface"},
		{"DEAUTH-FLOOD", "Attack Surface"},
		{"ROGUE-AP", "Attack Surface"},
		{"KARMA", "Rogue Access Point"},
		{"KARMA-AP", "Rogue Access Point"},
		{"KARMA-CLIENT", "Rogue Access Point"},
		{"ZERO-NONCE", "Cryptographic Flaw"},
		{"BAD-RNG", "Cryptographic Flaw"},
		{"WEAK-CRYPTO", "Cryptographic Flaw"},
		{"UNKNOWN-VULN", "Other"},
	}

	for _, tt := range tests {
		t.Run(tt.vulnName, func(t *testing.T) {
			result := generator.inferCategory(tt.vulnName)
			if result != tt.expected {
				t.Errorf("inferCategory(%v) = %v, want %v", tt.vulnName, result, tt.expected)
			}
		})
	}
}

func TestFilterByDateRange(t *testing.T) {
	generator := &ExecutiveReportGenerator{}

	now := time.Now()
	vulns := []domain.VulnerabilityRecord{
		{Name: "OLD", FirstSeen: now.AddDate(0, 0, -60)},
		{Name: "IN-RANGE-1", FirstSeen: now.AddDate(0, 0, -20)},
		{Name: "IN-RANGE-2", FirstSeen: now.AddDate(0, 0, -10)},
		{Name: "FUTURE", FirstSeen: now.AddDate(0, 0, 10)},
	}

	dateRange := domain.DateRange{
		Start: now.AddDate(0, 0, -30),
		End:   now,
	}

	filtered := generator.filterByDateRange(vulns, dateRange)

	// Should only include IN-RANGE-1 and IN-RANGE-2
	if len(filtered) != 2 {
		t.Errorf("Expected 2 vulnerabilities in range, got %d", len(filtered))
	}

	for _, v := range filtered {
		if v.Name != "IN-RANGE-1" && v.Name != "IN-RANGE-2" {
			t.Errorf("Unexpected vulnerability in filtered results: %v", v.Name)
		}
	}
}

func TestFilterByDateRangeZeroRange(t *testing.T) {
	generator := &ExecutiveReportGenerator{}

	vulns := []domain.VulnerabilityRecord{
		{Name: "VULN-1"},
		{Name: "VULN-2"},
		{Name: "VULN-3"},
	}

	// Zero date range should return all
	dateRange := domain.DateRange{}

	filtered := generator.filterByDateRange(vulns, dateRange)

	if len(filtered) != len(vulns) {
		t.Errorf("Zero date range should return all vulnerabilities, got %d/%d", len(filtered), len(vulns))
	}
}

// Integration test with realistic data
func TestExecutiveReportGeneratorIntegration(t *testing.T) {
	// Create realistic vulnerability data
	mockStorage := &MockStorage{
		vulnerabilities: []domain.VulnerabilityRecord{
			// Critical WPS vulnerabilities
			{Name: "WPS-PIXIE", Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:01", FirstSeen: time.Now()},
			{Name: "WPS-PIXIE", Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:02", FirstSeen: time.Now()},
			{Name: "WPS-PIXIE", Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:03", FirstSeen: time.Now()},
			// Open networks
			{Name: "OPEN-NETWORK", Severity: domain.Severity(8), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:04", FirstSeen: time.Now()},
			{Name: "OPEN-NETWORK", Severity: domain.Severity(8), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:05", FirstSeen: time.Now()},
			// Default SSIDs
			{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:06", FirstSeen: time.Now()},
			{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:07", FirstSeen: time.Now()},
			{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:08", FirstSeen: time.Now()},
			// Client vulnerabilities
			{Name: "PROBE-LEAKAGE", Severity: domain.Severity(4), Confidence: domain.Confidence(0.7), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:09", FirstSeen: time.Now()},
			{Name: "PROBE-LEAKAGE", Severity: domain.Severity(4), Confidence: domain.Confidence(0.7), Status: domain.VulnStatusActive, DeviceMAC: "00:11:22:33:44:10", FirstSeen: time.Now()},
			// Fixed vulnerability (should not affect risk much)
			{Name: "WEP", Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusFixed, DeviceMAC: "00:11:22:33:44:11", FirstSeen: time.Now()},
		},
	}

	generator := NewExecutiveReportGenerator(mockStorage, &MockDeviceRegistry{})

	dateRange := domain.DateRange{
		Start: time.Now().AddDate(0, 0, -7),
		End:   time.Now().AddDate(0, 0, 1),
	}

	report, err := generator.Generate(context.Background(), dateRange, "Security Test Corp")

	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Verify comprehensive report
	t.Logf("Report ID: %s", report.Metadata.ID)
	t.Logf("Risk Score: %.2f/10 (%s)", report.RiskScore, report.RiskLevel)
	t.Logf("Total Devices: %d", report.TotalDevices)
	t.Logf("Total Vulnerabilities: %d", report.VulnStats.Total)
	t.Logf("Critical: %d, High: %d, Medium: %d, Low: %d",
		report.VulnStats.Critical, report.VulnStats.High, report.VulnStats.Medium, report.VulnStats.Low)
	t.Logf("Top Risks: %d", len(report.TopRisks))
	t.Logf("Recommendations: %d", len(report.Recommendations))

	// Assertions
	if report.TotalDevices != 11 {
		t.Errorf("Expected 11 devices, got %d", report.TotalDevices)
	}

	if report.VulnStats.Total != 11 {
		t.Errorf("Expected 11 total vulnerabilities, got %d", report.VulnStats.Total)
	}

	// Risk should be high due to multiple critical vulnerabilities
	if report.RiskScore < 6.0 {
		t.Errorf("Risk score should be >= 6.0 with this data, got %.2f", report.RiskScore)
	}

	// Top risk should be WPS-PIXIE (3 devices, severity 10)
	if len(report.TopRisks) > 0 && report.TopRisks[0].VulnName != "WPS-PIXIE" {
		t.Errorf("Top risk should be WPS-PIXIE, got %v", report.TopRisks[0].VulnName)
	}

	// Should have recommendations
	if len(report.Recommendations) < 3 {
		t.Errorf("Expected at least 3 recommendations, got %d", len(report.Recommendations))
	}
}
