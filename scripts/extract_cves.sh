#!/bin/bash
# Extract CVEs from NVD for a specific vendor
# Usage: ./extract_cves.sh <vendor> [output_file]

set -e

VENDOR=${1:-"cisco"}
OUTPUT=${2:-"cves_${VENDOR}.json"}
API_KEY=${NVD_API_KEY:-""}

echo "Extracting CVEs for vendor: $VENDOR"
echo "Output file: $OUTPUT"

# Build API URL
URL="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${VENDOR}+wireless&resultsPerPage=100"

# Make request with optional API key
if [ -n "$API_KEY" ]; then
    echo "Using API key for higher rate limit"
    RESPONSE=$(curl -s "$URL" -H "apiKey: $API_KEY")
else
    echo "No API key set. Using default rate limit (5 req/30s)"
    RESPONSE=$(curl -s "$URL")
fi

# Parse and transform response
echo "$RESPONSE" | jq -r '.vulnerabilities[] | 
    {
      cve_id: .cve.id,
      vendor: "'${VENDOR}'",
      product: "unknown",
      description: .cve.descriptions[0].value,
      severity: (.cve.metrics.cvssMetricV31[0].cvssData.baseScore // 0),
      cvss_vector: (.cve.metrics.cvssMetricV31[0].cvssData.vectorString // ""),
      published_date: .cve.published,
      last_modified: (.cve.lastModified // .cve.published),
      attack_vector: (.cve.metrics.cvssMetricV31[0].cvssData.attackVector // "NETWORK"),
      cwe_id: (.cve.weaknesses[0].description[0].value // ""),
      references: [.cve.references[].url]
    }' | jq -s '.' > "$OUTPUT"

COUNT=$(jq length "$OUTPUT")
echo "✓ Extracted $COUNT CVEs to $OUTPUT"

# Show summary
echo ""
echo "Summary:"
jq -r 'group_by(.severity >= 9) | 
    map({
        severity: (if .[0].severity >= 9 then "Critical (≥9)" else "High/Medium (<9)" end),
        count: length
    })' "$OUTPUT"
