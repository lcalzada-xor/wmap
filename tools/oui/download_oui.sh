#!/bin/bash
# Download IEEE OUI database with proper headers

set -e

cd "$(dirname "$0")/../../.."

echo "Downloading IEEE OUI database..."

# Create data directory
mkdir -p data/oui

# Download with User-Agent header
curl -A "Mozilla/5.0 (X11; Linux x86_64) WMAP-OUI-Updater/1.0" \
     -L "https://standards-oui.ieee.org/oui/oui.txt" \
     -o data/oui/ieee_oui.txt

echo "Downloaded IEEE OUI database to data/oui/ieee_oui.txt"

# Convert to CSV format
echo "Converting to CSV format..."

cat > data/oui/ieee_oui.csv << 'HEADER'
Registry,Assignment,Organization Name,Organization Address
HEADER

# Parse the text file and convert to CSV
# Format: XX-XX-XX   (hex)		Organization Name
#                                 Address Line 1
#                                 Address Line 2

awk '
/^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}/ {
    # Extract OUI and organization name
    oui = $1
    gsub(/-/, ":", oui)  # Convert to XX:XX:XX format
    
    # Get organization name (everything after hex and whitespace)
    org = substr($0, index($0, "(hex)") + 6)
    gsub(/^[ \t]+/, "", org)  # Trim leading whitespace
    gsub(/"/, "\"\"", org)     # Escape quotes
    
    # Read next line for address
    getline
    addr = $0
    gsub(/^[ \t]+/, "", addr)  # Trim leading whitespace
    gsub(/"/, "\"\"", addr)    # Escape quotes
    
    # Print CSV line
    printf "MA-L,%s,\"%s\",\"%s\"\n", oui, org, addr
}
' data/oui/ieee_oui.txt >> data/oui/ieee_oui.csv

echo "Converted to CSV format: data/oui/ieee_oui.csv"

# Count entries
count=$(grep -c "^MA-L" data/oui/ieee_oui.csv || true)
echo "Total OUI entries: $count"

echo "✓ Download complete!"
echo ""
echo "Now run: ./bin/oui-updater --source ieee --db data/oui/ieee_oui.db"
