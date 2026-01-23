#!/bin/bash
# Generate comprehensive seed data for multiple vendors
# Usage: ./generate_seed.sh

set -e

VENDORS=("cisco" "tplink" "netgear" "dlink" "linksys" "ubiquiti" "huawei" "zte" "sagemcom" "comtrend" "mitel")
OUTPUT_DIR="./configs"
FINAL_OUTPUT="${OUTPUT_DIR}/cve_seed_full.json"

echo "=== CVE Seed Generator ==="
echo "Extracting CVEs for ${#VENDORS[@]} vendors..."
echo ""

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

cd "$(dirname "$0")/.."

for vendor in "${VENDORS[@]}"; do
    echo "[$vendor] Extracting..."
    
    if ./scripts/extract_cves.sh "$vendor" "$TEMP_DIR/cves_${vendor}.json"; then
        echo "[$vendor] ✓ Success"
    else
        echo "[$vendor] ✗ Failed"
    fi
    
    # Rate limiting (6 seconds between requests)
    if [ "$vendor" != "${VENDORS[-1]}" ]; then
        echo "Waiting 6 seconds (rate limiting)..."
        sleep 6
    fi
    echo ""
done

echo "Merging all CVE files..."
jq -s 'add | unique_by(.cve_id)' $TEMP_DIR/cves_*.json > "$FINAL_OUTPUT"

TOTAL_COUNT=$(jq length "$FINAL_OUTPUT")
echo "✓ Generated $FINAL_OUTPUT with $TOTAL_COUNT unique CVEs"

echo ""
echo "=== Summary by Vendor ==="
jq -r 'group_by(.vendor) | 
    map({
        vendor: .[0].vendor,
        count: length,
        avg_severity: (map(.severity) | add / length | floor * 10 / 10)
    }) | 
    .[] | 
    "\(.vendor): \(.count) CVEs (avg severity: \(.avg_severity))"' "$FINAL_OUTPUT"

echo ""
echo "=== Summary by Severity ==="
jq -r 'group_by(
    if .severity >= 9 then "Critical"
    elif .severity >= 7 then "High"
    elif .severity >= 4 then "Medium"
    else "Low"
    end
) | 
map({
    level: (if .[0].severity >= 9 then "Critical (≥9.0)"
            elif .[0].severity >= 7 then "High (7.0-8.9)"
            elif .[0].severity >= 4 then "Medium (4.0-6.9)"
            else "Low (<4.0)" end),
    count: length
}) | 
.[] | 
"\(.level): \(.count) CVEs"' "$FINAL_OUTPUT"

echo ""
echo "Done! Load with:"
echo "  go run cmd/cve_loader/main.go --seed-file=$FINAL_OUTPUT"
