package cve

import (
	"context"
	"sort"
	"strings"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// CVEMatcherEngine implements ports.CVEMatcher.
type CVEMatcherEngine struct {
	repo ports.CVERepository
}

// NewCVEMatcher creates a new CVE matcher engine.
func NewCVEMatcher(repo ports.CVERepository) *CVEMatcherEngine {
	return &CVEMatcherEngine{repo: repo}
}

// FindMatches returns all CVE matches for a given device using multiple strategies.
func (m *CVEMatcherEngine) FindMatches(ctx context.Context, device domain.Device) ([]domain.CVEMatch, error) {
	var matches []domain.CVEMatch

	// Strategy 1: Exact Vendor + Product Match
	if device.Vendor != "" && device.Model != "" {
		exactMatches, err := m.matchExact(ctx, device)
		if err == nil {
			matches = append(matches, exactMatches...)
		}
	}

	// Strategy 2: WPS Details (Manufacturer + Model)
	if device.WPSDetails != nil && device.WPSDetails.Manufacturer != "" {
		wpsMatches, err := m.matchWPS(ctx, device)
		if err == nil {
			matches = append(matches, wpsMatches...)
		}
	}

	// Strategy 3: Keyword-based (Fuzzy)
	keywordMatches, err := m.matchKeywords(ctx, device)
	if err == nil {
		matches = append(matches, keywordMatches...)
	}

	// Deduplicate and sort by confidence DESC, then severity DESC
	return m.deduplicateAndSort(matches), nil
}

// matchExact performs exact vendor/product matching.
func (m *CVEMatcherEngine) matchExact(ctx context.Context, device domain.Device) ([]domain.CVEMatch, error) {
	vendor := normalizeVendor(device.Vendor)
	product := normalizeProduct(device.Model)

	cves, err := m.repo.FindByVendorProduct(ctx, vendor, product)
	if err != nil {
		return nil, err
	}

	var matches []domain.CVEMatch
	for _, cve := range cves {
		matches = append(matches, domain.CVEMatch{
			CVE:        cve,
			Confidence: 0.9, // High confidence for exact match
			MatchType:  "exact",
			Evidence: []string{
				"Vendor: " + device.Vendor,
				"Model: " + device.Model,
			},
		})
	}

	return matches, nil
}

// matchWPS performs matching based on WPS manufacturer/model information.
func (m *CVEMatcherEngine) matchWPS(ctx context.Context, device domain.Device) ([]domain.CVEMatch, error) {
	if device.WPSDetails == nil {
		return nil, nil
	}

	vendor := normalizeVendor(device.WPSDetails.Manufacturer)
	product := normalizeProduct(device.WPSDetails.Model)

	// Skip if empty
	if vendor == "" || product == "" {
		return nil, nil
	}

	// Skip matching for generic terms that cause false positives
	if isGenericTerm(vendor) || isGenericTerm(product) {
		return nil, nil
	}

	cves, err := m.repo.FindByVendorProduct(ctx, vendor, product)
	if err != nil {
		return nil, err
	}

	var matches []domain.CVEMatch
	for _, cve := range cves {
		matches = append(matches, domain.CVEMatch{
			CVE:        cve,
			Confidence: 0.85, // Slightly lower than exact
			MatchType:  "wps",
			Evidence: []string{
				"WPS Manufacturer: " + device.WPSDetails.Manufacturer,
				"WPS Model: " + device.WPSDetails.Model,
			},
		})
	}

	return matches, nil
}

// matchKeywords performs fuzzy matching based on device capabilities and security features.
func (m *CVEMatcherEngine) matchKeywords(ctx context.Context, device domain.Device) ([]domain.CVEMatch, error) {
	keywords := extractKeywords(device)
	if len(keywords) == 0 {
		return nil, nil
	}

	cves, err := m.repo.SearchByKeywords(ctx, keywords)
	if err != nil {
		return nil, err
	}

	var matches []domain.CVEMatch
	deviceVendor := normalizeVendor(device.Vendor)

	for _, cve := range cves {
		cveVendor := normalizeVendor(cve.Vendor)

		// CRITICAL: False Positive Reduction
		// If the CVE is associated with a specific vendor (not * or generic),
		// and we know the device vendor, they MUST match.
		// Otherwise we might match a Cisco CVE to a Linksys device just because they both have "WPA2".
		if cveVendor != "*" && cveVendor != "" && deviceVendor != "" && deviceVendor != "unknown" {
			if cveVendor != deviceVendor {
				continue // Skip mismatching vendors
			}
		}

		// Calculate confidence based on keyword relevance
		confidence := 0.5 // Base confidence for keyword match

		// Boost confidence if vendor name appears in description
		if device.Vendor != "" && strings.Contains(strings.ToLower(cve.Description), strings.ToLower(device.Vendor)) {
			confidence = 0.7
		}

		// Penalize generic protocol matches slightly to prefer specific ones
		if cveVendor == "*" || cveVendor == "generic" {
			confidence = 0.4
		}

		matches = append(matches, domain.CVEMatch{
			CVE:        cve,
			Confidence: confidence,
			MatchType:  "keyword",
			Evidence:   []string{"Keywords: " + strings.Join(keywords, ", ")},
		})
	}

	return matches, nil
}

// extractKeywords extracts relevant keywords from device for fuzzy matching.
func extractKeywords(device domain.Device) []string {
	var keywords []string

	// Add security-related capabilities
	for _, cap := range device.Capabilities {
		capLower := strings.ToLower(cap)
		if strings.Contains(capLower, "wps") ||
			strings.Contains(capLower, "wpa") ||
			strings.Contains(capLower, "wep") {
			keywords = append(keywords, cap)
		}
	}

	// Add WiFi standard
	if device.Standard != "" {
		keywords = append(keywords, device.Standard)
	}

	// Add security protocol
	if device.Security != "" {
		keywords = append(keywords, device.Security)
	}

	return keywords
}

// normalizeVendor normalizes vendor names for consistent matching.
func normalizeVendor(vendor string) string {
	vendor = strings.ToLower(strings.TrimSpace(vendor))

	// Common vendor aliases
	aliases := map[string]string{
		"tp-link":  "tplink",
		"tp link":  "tplink",
		"d-link":   "dlink",
		"d link":   "dlink",
		"netgear":  "netgear",
		"cisco":    "cisco",
		"linksys":  "linksys",
		"asus":     "asus",
		"ubiquiti": "ubiquiti",
		"mikrotik": "mikrotik",
		"aruba":    "aruba",
		"ruckus":   "ruckus",
		"broadcom": "broadcom",
		"qualcomm": "qualcomm",
		"intel":    "intel",
		"realtek":  "realtek",
		"ralink":   "ralink",
		"mediatek": "mediatek",

		// Spanish/European ISP Vendors
		"huawei":              "huawei",
		"huawei technologies": "huawei",
		"zte":                 "zte",
		"zte corporation":     "zte",
		"sagemcom":            "sagemcom",
		"sagem":               "sagemcom",
		"comtrend":            "comtrend",
		"comtrend corp":       "comtrend",
		"mitel":               "mitel",
		"mitel networks":      "mitel",
		"observa":             "observa",
		"askey":               "askey",
		"sercomm":             "sercomm",
		"arcadyan":            "arcadyan",
	}

	if normalized, ok := aliases[vendor]; ok {
		return normalized
	}

	return vendor
}

// normalizeProduct normalizes product/model names.
func normalizeProduct(product string) string {
	product = strings.ToLower(strings.TrimSpace(product))

	// Remove common prefixes
	product = strings.TrimPrefix(product, "model ")
	product = strings.TrimPrefix(product, "model:")

	return product
}

// isGenericTerm checks if a string is a known generic term that shouldn't be used for matching.
func isGenericTerm(s string) bool {
	genericTerms := []string{
		"generic",
		"unknown",
		"wireless router",
		"wireless ap",
		"access point",
		"router",
		"gateway",
		"networking device",
		"draft n",
		"1.0",
		"2.0",
		"ralink", // Chipset manufacturer, confusingly used as vendor often
		"realtek",
		"broadcom",
		"atheros",
		"mediatek",
	}

	s = strings.ToLower(s)
	for _, term := range genericTerms {
		if s == term {
			return true
		}
	}
	return false
}

// deduplicateAndSort removes duplicate CVEs and sorts by confidence then severity.
func (m *CVEMatcherEngine) deduplicateAndSort(matches []domain.CVEMatch) []domain.CVEMatch {
	seen := make(map[string]*domain.CVEMatch)

	// Keep highest confidence match for each CVE
	for i := range matches {
		match := &matches[i]
		existing, exists := seen[match.CVE.ID]

		if !exists || match.Confidence > existing.Confidence {
			seen[match.CVE.ID] = match
		}
	}

	// Convert map to slice
	var unique []domain.CVEMatch
	for _, match := range seen {
		unique = append(unique, *match)
	}

	// Sort by confidence DESC, then severity DESC
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Confidence != unique[j].Confidence {
			return unique[i].Confidence > unique[j].Confidence
		}
		return unique[i].CVE.Severity > unique[j].CVE.Severity
	})

	return unique
}
