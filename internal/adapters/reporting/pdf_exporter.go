package reporting

import (
	"bytes"
	"fmt"

	"github.com/jung-kurt/gofpdf"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// PDFExporter exports reports to PDF format
type PDFExporter struct{}

// NewPDFExporter creates a new PDF exporter instance
func NewPDFExporter() *PDFExporter {
	return &PDFExporter{}
}

// ExportExecutiveSummary generates a professional PDF from an executive summary
func (e *PDFExporter) ExportExecutiveSummary(report *domain.ExecutiveSummary) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Header with title and organization
	e.addHeader(pdf, report)

	// Risk Score (prominent display)
	e.addRiskScore(pdf, report)

	// Statistics overview
	e.addStatistics(pdf, report)

	// Top Risks table
	e.addTopRisks(pdf, report)

	// Recommendations
	e.addRecommendations(pdf, report)

	// Footer
	e.addFooter(pdf, report)

	// Output to bytes
	var buf bytes.Buffer
	err := pdf.Output(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return buf.Bytes(), nil
}

// addHeader adds the report header
func (e *PDFExporter) addHeader(pdf *gofpdf.Fpdf, report *domain.ExecutiveSummary) {
	// Title
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(0, 51, 102) // Dark blue
	pdf.CellFormat(0, 15, report.Metadata.Title, "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// Organization
	if report.Metadata.OrganizationName != "" {
		pdf.SetFont("Arial", "", 14)
		pdf.SetTextColor(100, 100, 100) // Gray
		pdf.CellFormat(0, 8, report.Metadata.OrganizationName, "", 1, "L", false, 0, "")
		pdf.Ln(2)
	}

	// Date and period
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(120, 120, 120)
	dateStr := fmt.Sprintf("Generated: %s", report.Metadata.GeneratedAt.Format("2006-01-02 15:04"))
	pdf.CellFormat(0, 6, dateStr, "", 1, "L", false, 0, "")

	if !report.Metadata.ScanPeriod.Start.IsZero() {
		periodStr := fmt.Sprintf("Scan Period: %s to %s",
			report.Metadata.ScanPeriod.Start.Format("2006-01-02"),
			report.Metadata.ScanPeriod.End.Format("2006-01-02"))
		pdf.CellFormat(0, 6, periodStr, "", 1, "L", false, 0, "")
	}

	pdf.Ln(8)
}

// addRiskScore adds the prominent risk score display
func (e *PDFExporter) addRiskScore(pdf *gofpdf.Fpdf, report *domain.ExecutiveSummary) {
	// Get risk color
	r, g, b := e.getRiskColor(report.RiskScore)

	// Draw colored box
	pdf.SetFillColor(r, g, b)
	pdf.Rect(20, pdf.GetY(), 170, 30, "F")

	// Save Y position
	y := pdf.GetY()

	// Risk score number
	pdf.SetFont("Arial", "B", 36)
	pdf.SetTextColor(255, 255, 255) // White
	pdf.SetXY(25, y+5)
	scoreStr := fmt.Sprintf("%.1f/10", report.RiskScore)
	pdf.CellFormat(80, 20, scoreStr, "", 0, "L", false, 0, "")

	// Risk level text
	pdf.SetFont("Arial", "B", 18)
	pdf.SetXY(110, y+8)
	levelStr := fmt.Sprintf("%s Risk", report.RiskLevel)
	pdf.CellFormat(80, 14, levelStr, "", 0, "L", false, 0, "")

	pdf.SetY(y + 35)
	pdf.Ln(5)
}

// getRiskColor returns RGB color based on risk score
func (e *PDFExporter) getRiskColor(score float64) (r, g, b int) {
	switch {
	case score >= 8.0:
		return 220, 53, 69 // Red (Critical)
	case score >= 6.0:
		return 255, 149, 0 // Orange (High)
	case score >= 4.0:
		return 255, 204, 0 // Yellow (Medium)
	default:
		return 52, 199, 89 // Green (Low)
	}
}

// addStatistics adds vulnerability statistics
func (e *PDFExporter) addStatistics(pdf *gofpdf.Fpdf, report *domain.ExecutiveSummary) {
	// Section title
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 51, 102)
	pdf.CellFormat(0, 10, "Security Overview", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// Statistics grid
	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(60, 60, 60)

	stats := []struct {
		label string
		value string
		color []int
	}{
		{"Total Devices", fmt.Sprintf("%d", report.TotalDevices), []int{0, 102, 204}},
		{"Total Vulnerabilities", fmt.Sprintf("%d", report.VulnStats.Total), []int{0, 102, 204}},
		{"Critical", fmt.Sprintf("%d", report.VulnStats.Critical), []int{220, 53, 69}},
		{"High", fmt.Sprintf("%d", report.VulnStats.High), []int{255, 149, 0}},
		{"Medium", fmt.Sprintf("%d", report.VulnStats.Medium), []int{255, 204, 0}},
		{"Low", fmt.Sprintf("%d", report.VulnStats.Low), []int{52, 199, 89}},
		{"Confirmed", fmt.Sprintf("%d", report.VulnStats.Confirmed), []int{0, 102, 204}},
		{"Unconfirmed", fmt.Sprintf("%d", report.VulnStats.Unconfirmed), []int{150, 150, 150}},
	}

	// Display in 2 columns
	colWidth := 85.0
	for i, stat := range stats {
		x := 20.0
		if i%2 == 1 {
			x = 105.0
		}

		pdf.SetXY(x, pdf.GetY())

		// Label
		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(50, 7, stat.label+":", "", 0, "L", false, 0, "")

		// Value
		pdf.SetFont("Arial", "B", 11)
		pdf.SetTextColor(stat.color[0], stat.color[1], stat.color[2])
		pdf.CellFormat(colWidth-50, 7, stat.value, "", 0, "R", false, 0, "")

		if i%2 == 1 {
			pdf.Ln(7)
		}
	}

	pdf.Ln(10)
}

// addTopRisks adds the top risks table
func (e *PDFExporter) addTopRisks(pdf *gofpdf.Fpdf, report *domain.ExecutiveSummary) {
	// Section title
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 51, 102)
	pdf.CellFormat(0, 10, "Top Security Risks", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	if len(report.TopRisks) == 0 {
		pdf.SetFont("Arial", "I", 10)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(0, 7, "No active risks identified", "", 1, "L", false, 0, "")
		pdf.Ln(5)
		return
	}

	// Table header
	pdf.SetFillColor(240, 240, 240)
	pdf.SetFont("Arial", "B", 10)
	pdf.SetTextColor(60, 60, 60)

	pdf.CellFormat(15, 8, "Rank", "1", 0, "C", true, 0, "")
	pdf.CellFormat(55, 8, "Vulnerability", "1", 0, "L", true, 0, "")
	pdf.CellFormat(25, 8, "Severity", "1", 0, "C", true, 0, "")
	pdf.CellFormat(30, 8, "Devices", "1", 0, "C", true, 0, "")
	pdf.CellFormat(45, 8, "Impact", "1", 1, "L", true, 0, "")

	// Table rows
	pdf.SetFont("Arial", "", 9)
	for _, risk := range report.TopRisks {
		// Severity color
		r, g, b := e.getSeverityColor(risk.Severity)
		pdf.SetTextColor(r, g, b)

		pdf.CellFormat(15, 7, fmt.Sprintf("%d", risk.Rank), "1", 0, "C", false, 0, "")

		pdf.SetTextColor(60, 60, 60)
		pdf.CellFormat(55, 7, risk.VulnName, "1", 0, "L", false, 0, "")

		pdf.SetTextColor(r, g, b)
		pdf.CellFormat(25, 7, fmt.Sprintf("%d/10", risk.Severity), "1", 0, "C", false, 0, "")

		pdf.SetTextColor(60, 60, 60)
		pdf.CellFormat(30, 7, fmt.Sprintf("%d", risk.AffectedDevices), "1", 0, "C", false, 0, "")

		// Truncate impact if too long
		impact := risk.Impact
		if len(impact) > 30 {
			impact = impact[:27] + "..."
		}
		pdf.CellFormat(45, 7, impact, "1", 1, "L", false, 0, "")
	}

	pdf.Ln(8)
}

// getSeverityColor returns RGB color based on severity
func (e *PDFExporter) getSeverityColor(severity int) (r, g, b int) {
	switch {
	case severity >= 9:
		return 220, 53, 69 // Red
	case severity >= 7:
		return 255, 149, 0 // Orange
	case severity >= 4:
		return 255, 204, 0 // Yellow
	default:
		return 52, 199, 89 // Green
	}
}

// addRecommendations adds the recommendations section
func (e *PDFExporter) addRecommendations(pdf *gofpdf.Fpdf, report *domain.ExecutiveSummary) {
	// Section title
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 51, 102)
	pdf.CellFormat(0, 10, "Priority Recommendations", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	for i, rec := range report.Recommendations {
		if i >= 5 { // Limit to 5 recommendations
			break
		}

		// Check if we need a new page
		if pdf.GetY() > 250 {
			pdf.AddPage()
		}

		// Priority badge
		r, g, b := e.getPriorityColor(rec.Priority)
		pdf.SetFillColor(r, g, b)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Arial", "B", 9)
		pdf.CellFormat(25, 6, rec.Priority, "", 0, "C", true, 0, "")

		// Title
		pdf.SetFont("Arial", "B", 11)
		pdf.SetTextColor(0, 51, 102)
		pdf.CellFormat(0, 6, "  "+rec.Title, "", 1, "L", false, 0, "")
		pdf.Ln(1)

		// Description
		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(60, 60, 60)
		pdf.MultiCell(0, 5, rec.Description, "", "L", false)
		pdf.Ln(1)

		// Actions
		pdf.SetFont("Arial", "B", 9)
		pdf.SetTextColor(80, 80, 80)
		pdf.CellFormat(0, 5, "Actions:", "", 1, "L", false, 0, "")

		pdf.SetFont("Arial", "", 9)
		for _, action := range rec.Actions {
			if len(action) > 100 {
				action = action[:97] + "..."
			}
			pdf.CellFormat(5, 5, "", "", 0, "L", false, 0, "")
			pdf.CellFormat(0, 5, "• "+action, "", 1, "L", false, 0, "")
		}

		// Effort
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(0, 5, fmt.Sprintf("Estimated Effort: %s", rec.EstimatedEffort), "", 1, "L", false, 0, "")

		pdf.Ln(5)
	}
}

// getPriorityColor returns RGB color based on priority
func (e *PDFExporter) getPriorityColor(priority string) (r, g, b int) {
	switch priority {
	case "critical":
		return 220, 53, 69 // Red
	case "high":
		return 255, 149, 0 // Orange
	case "medium":
		return 255, 204, 0 // Yellow
	default:
		return 52, 199, 89 // Green
	}
}

// addFooter adds the report footer
func (e *PDFExporter) addFooter(pdf *gofpdf.Fpdf, report *domain.ExecutiveSummary) {
	// Move to bottom
	pdf.SetY(-20)

	// Separator line
	pdf.SetDrawColor(200, 200, 200)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(3)

	// Footer text
	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(120, 120, 120)
	footerText := fmt.Sprintf("Generated by %s | Report ID: %s",
		report.Metadata.GeneratedBy,
		report.Metadata.ID[:8])
	pdf.CellFormat(0, 5, footerText, "", 1, "C", false, 0, "")
}
