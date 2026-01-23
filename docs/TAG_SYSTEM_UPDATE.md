# Vulnerability Tags System - Update Documentation

## Overview
The vulnerability tags system in the frontend (`attack_tags.js`) has been updated to support the new passive scanning detections.

---

## New Tags Added

### 1. KARMA (Rogue Access Point)
**Trigger**: `node.observed_ssids.length > 1`  
**Color**: `#ff3b30` (Critical Red)  
**Severity**: 10  
**Description**: Displays when an AP broadcasts multiple SSIDs from the same BSSID  
**Example**: `[KARMA]` with tooltip "Rogue AP (3 SSIDs)"

**Visual Appearance**:
```
[KARMA] [WPS] [PMKID]
```

---

### 2. KARMA-CLIENT (Excessive Probing)
**Trigger**: `Object.keys(node.probed_ssids).length > 5`  
**Color**: `#ff9500` (High Orange)  
**Severity**: 5  
**Description**: Client probing more than 5 networks  
**Example**: `[KARMA-CLIENT]` with tooltip "Probing 8 networks"

**Use Case**: Identifies clients with large Preferred Network Lists (PNL) that leak privacy

---

### 3. PMKID (Offline PSK Cracking)
**Trigger**: `node.vulnerabilities` contains "PMKID" or "PMKID-EXPOSURE"  
**Color**: `#ff9500` (High Orange)  
**Severity**: 8  
**Description**: AP exposes PMKID in EAPOL M1  
**Example**: `[PMKID]` with tooltip "Offline PSK Cracking"

**Attack Vector**: Allows offline dictionary attacks without capturing full handshake

---

### 4. FT-PSK (Fast Roaming Vulnerability)
**Trigger**: `node.has_11r && security.includes('PSK')`  
**Color**: `#ffcc00` (Medium Yellow)  
**Severity**: 6  
**Description**: 802.11r Fast Transition with PSK  
**Example**: `[FT-PSK]` with tooltip "Fast Roaming + PSK"

**Risk**: FT-PSK is more susceptible to offline attacks than standard WPA2-PSK

---

### 5. WEAK-CRYPTO (Cryptographic Anomalies)
**Trigger**: `node.crypto_anomaly` (set by backend)  
**Color**: `#ff3b30` (Critical Red)  
**Severity**: 10  
**Description**: RNG failures, Zero Nonce, or other crypto flaws  
**Example**: `[WEAK-CRYPTO]` with tooltip "Zero Nonce detected"

**Detection**: Populated by M1 analysis in `eapol_handler.go`

---

## Tag Priority System

Tags are sorted by severity (highest first):

```javascript
Severity 10: KARMA, WEAK-CRYPTO, WEP, UNSECURE
Severity 8:  PMKID
Severity 7:  WPS
Severity 6:  FT-PSK
Severity 5:  KARMA-CLIENT
Severity 2:  WPA3
```

**Display Limit**: Top 3 tags shown in graph labels to avoid clutter

---

## Color Coding

| Color | Hex | Severity Range | Usage |
|-------|-----|----------------|-------|
| Red | `#ff3b30` | 9-10 | Critical vulnerabilities |
| Orange | `#ff9500` | 7-8 | High severity |
| Yellow | `#ffcc00` | 5-6 | Medium severity |
| Green | `#34c759` | 3-4 | Low severity |
| Blue | `#007aff` | 0-2 | Informational |

---

## Integration Points

### 1. Graph Labels
**File**: `core/graph_filter.js`  
**Usage**: Filters nodes by tag labels
```javascript
const tags = AttackTags.getTags(node).map(t => t.label);
```

### 2. Device Details Panel
**File**: `ui/hud_templates.js`  
**Usage**: Displays tags as colored badges
```javascript
const tags = AttackTags.getTags(n);
// Renders: <span class="quick-filter-btn" style="background:${t.color}20">
```

### 3. Node Styling
**Usage**: Visual indicators on graph nodes
```javascript
const formattedLabel = AttackTags.formatLabel(originalLabel, tags);
// Result: "MyNetwork\n[KARMA] [WPS]"
```

---

## Backend Integration

Tags can come from two sources:

### A. Backend Vulnerabilities (Preferred)
```javascript
if (node.vulnerabilities && node.vulnerabilities.length > 0) {
    tags = node.vulnerabilities.map(v => ({
        label: `${v.name}${confChar}`,
        color: this.getSeverityColor(v.severity),
        desc: v.description,
        confidence: v.confidence,
        severity: v.severity,
        backend: true
    }));
}
```

### B. Frontend Heuristics (Fallback)
Checks for:
- `node.security` (WEP, WPS, OPEN)
- `node.observed_ssids` (Karma)
- `node.has_11r` (FT-PSK)
- `node.probed_ssids` (Karma Client)

---

## Example Output

### Rogue AP with Multiple Vulnerabilities
```
Node: "FreeWiFi"
Tags: [KARMA] [WPS] [PMKID]
Tooltip: 
  - KARMA: Rogue AP (4 SSIDs)
  - WPS: Pixie Dust / Reaver
  - PMKID: Offline PSK Cracking
```

### Compromised Crypto AP
```
Node: "HomeNetwork"
Tags: [WEAK-CRYPTO] [FT-PSK]
Tooltip:
  - WEAK-CRYPTO: Zero Nonce detected
  - FT-PSK: Fast Roaming + PSK
```

### Suspicious Client
```
Node: "iPhone-12"
Tags: [KARMA-CLIENT]
Tooltip:
  - KARMA-CLIENT: Probing 12 networks
```

---

## Testing

### Manual Test Cases

1. **Karma AP**:
   - Create device with `observed_ssids: ["Net1", "Net2", "Net3"]`
   - Expected: Red `[KARMA]` tag with severity 10

2. **PMKID**:
   - Device with `vulnerabilities: [{name: "PMKID", severity: 8}]`
   - Expected: Orange `[PMKID]` tag

3. **FT-PSK**:
   - Device with `has_11r: true, security: "WPA2-PSK"`
   - Expected: Yellow `[FT-PSK]` tag

4. **Karma Client**:
   - Device with `probed_ssids: {net1: ..., net2: ..., [6 total]}`
   - Expected: Orange `[KARMA-CLIENT]` tag

---

## Future Enhancements

1. **CVE Integration**: Display CVE IDs as tags (e.g., `[CVE-2020-1234]`)
2. **Confidence Indicators**: Show `?` suffix for low-confidence detections
3. **Interactive Tooltips**: Click tag to show mitigation steps
4. **Tag Filtering**: Filter graph by specific tag types

---

## Files Modified

- ✅ `internal/adapters/web/static/js/core/attack_tags.js` - Core tag logic
- 📝 Documentation created

## Compatibility

- **Backward Compatible**: ✅ Yes
- **Requires Backend Changes**: ❌ No (uses existing fields)
- **Breaking Changes**: ❌ None
