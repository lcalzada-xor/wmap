#!/bin/bash
# Script to populate OUI database from local static data
# This is a temporary solution until we can download from IEEE

cd "$(dirname "$0")/../../.."

echo "Creating OUI database from static data..."

# Create data directory if it doesn't exist
mkdir -p data/oui

# Create a simple CSV with common OUIs
cat > data/oui/sample_oui.csv << 'EOF'
Registry,Assignment,Organization Name,Organization Address
MA-L,00:00:00,XEROX CORPORATION,"M/S 105-50C 800 PHILLIPS ROAD WEBSTER NY 14580 US"
MA-L,00:00:01,XEROX CORPORATION,"M/S 105-50C 800 PHILLIPS ROAD WEBSTER NY 14580 US"
MA-L,00:03:93,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:05:02,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:0A:27,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:0A:95,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:17:F2,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:1B:63,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:1C:B3,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:1E:C2,Apple Inc.,"1 Infinite Loop Cupertino CA 95014 US"
MA-L,00:00:F0,Samsung Electronics Co. Ltd,"416 MAETAN-3DONG YEONGTONG-GU SUWON-SI GYEONGGI-DO 443-742 KR"
MA-L,00:02:78,Samsung Electronics Co. Ltd,"416 MAETAN-3DONG YEONGTONG-GU SUWON-SI GYEONGGI-DO 443-742 KR"
MA-L,00:12:47,Samsung Electronics Co. Ltd,"416 MAETAN-3DONG YEONGTONG-GU SUWON-SI GYEONGGI-DO 443-742 KR"
MA-L,00:13:77,Samsung Electronics Co. Ltd,"416 MAETAN-3DONG YEONGTONG-GU SUWON-SI GYEONGGI-DO 443-742 KR"
MA-L,00:1A:11,Google Inc.,"1600 Amphitheatre Parkway Mountain View CA 94043 US"
MA-L,3C:5A:B4,Google Inc.,"1600 Amphitheatre Parkway Mountain View CA 94043 US"
MA-L,54:60:09,Google Inc.,"1600 Amphitheatre Parkway Mountain View CA 94043 US"
MA-L,00:15:6D,Ubiquiti Networks Inc.,"685 Third Avenue New York NY 10017 US"
MA-L,00:27:22,Ubiquiti Networks Inc.,"685 Third Avenue New York NY 10017 US"
MA-L,04:18:D6,Ubiquiti Networks Inc.,"685 Third Avenue New York NY 10017 US"
MA-L,18:FE:34,Espressif Inc.,"Room 204 Building 2 690 Bibo Rd Zhangjiang High-tech Park Pudong Shanghai 201203 CN"
MA-L,24:0A:C4,Espressif Inc.,"Room 204 Building 2 690 Bibo Rd Zhangjiang High-tech Park Pudong Shanghai 201203 CN"
MA-L,24:62:AB,Espressif Inc.,"Room 204 Building 2 690 Bibo Rd Zhangjiang High-tech Park Pudong Shanghai 201203 CN"
MA-L,00:03:7F,TP-LINK TECHNOLOGIES CO. LTD.,"ROOM 901 9/F BUILD C1 TSINGHUA SCIENCE PARK SHENZHEN GUANGDONG 518057 CN"
MA-L,00:0A:EB,TP-LINK TECHNOLOGIES CO. LTD.,"ROOM 901 9/F BUILD C1 TSINGHUA SCIENCE PARK SHENZHEN GUANGDONG 518057 CN"
MA-L,00:50:56,VMware Inc.,"3401 Hillview Avenue Palo Alto CA 94304 US"
MA-L,B8:27:EB,Raspberry Pi Foundation,"Maurice Wilkes Building Cowley Road Cambridge CB4 0DS GB"
MA-L,DC:A6:32,Raspberry Pi Foundation,"Maurice Wilkes Building Cowley Road Cambridge CB4 0DS GB"
MA-L,00:02:B3,Intel Corporation,"LOT 8 JALAN HI-TECH 2/3 KULIM HI-TECH PARK 09000 KULIM KEDAH MY"
MA-L,00:03:47,Intel Corporation,"LOT 8 JALAN HI-TECH 2/3 KULIM HI-TECH PARK 09000 KULIM KEDAH MY"
MA-L,00:04:23,Intel Corporation,"LOT 8 JALAN HI-TECH 2/3 KULIM HI-TECH PARK 09000 KULIM KEDAH MY"
MA-L,74:E5:43,Xiaomi Communications Co Ltd,"No.006 FLOOR 6 BUILDING 6 YARD 33 MIDDLE XIERQI ROAD HAIDIAN DISTRICT BEIJING 100085 CN"
MA-L,D8:63:75,Xiaomi Communications Co Ltd,"No.006 FLOOR 6 BUILDING 6 YARD 33 MIDDLE XIERQI ROAD HAIDIAN DISTRICT BEIJING 100085 CN"
EOF

echo "Sample OUI CSV created at data/oui/sample_oui.csv"
echo "This contains ~30 common OUI entries for testing."
echo ""
echo "Note: For production, you should download the full IEEE registry."
echo "The full registry contains 50,000+ entries and can be obtained from:"
echo "  - https://standards-oui.ieee.org/oui/oui.txt (text format)"
echo "  - https://maclookup.app/downloads/csv-database (CSV format)"
echo ""
echo "For now, the system will use the static fallback map in oui_data.go"
