# Implementation Plan: Short-Term Passive Scanning Improvements

## Goal
Implement the "Alert & Precision" phase improvements defined in the Maturity Report. This focuses on maximizing the value of currently captured data to detect advanced threats passively.

## Phases

### Phase 1: Advanced Karma/Mana Detection (AP-Side)
**Objective**: Detect malicious APs that respond to Probe Requests for multiple different SSIDs using the same BSSID.
**Changes**:
- `internal/core/domain/device.go`: Add `ObservedSSIDs` field to `Device` struct to track all SSIDs advertised by an AP (BSSID).
- `internal/adapters/sniffer/parser/packet_handler.go`: Update `handleMgmtFrame` to append seen SSIDs from Probe Responses to the Device.
- `internal/core/services/security/detectors.go`: Implement `KarmaAPDetector` (distinct from existing `KarmaDetector` which checks clients). Logic: If single BSSID advertises multiple distinct SSIDs -> High Probability of Karma/Mana.

### Phase 2: 802.11r Fast Roaming Analysis
**Objective**: Detect insecure Fast Roaming configurations (e.g., weak ciphers in FT) passively.
**Changes**:
- `internal/adapters/sniffer/ie/rsn.go` (or new `mdie.go`): Extract Mobility Domain IE (MDIE) parsing logic.
- `internal/core/domain/device.go`: Add `MobilityDomain` details.
- `internal/core/services/security/vulnerability_detector.go`: Add check for FT configuration issues (e.g., FT over DS with weak auth).

### Phase 3: Partial Handshake Analysis (M1)
**Objective**: Analyze EAPOL M1 frames to validate AP randomness and configuration without needing a full handshake.
**Changes**:
- `internal/adapters/sniffer/parser/packet_handler.go`: Enhance `detectPMKID` or separate flow to inspect M1 Key Nonce.
- `internal/core/services/security/vulnerability_detector.go`: Add check for "Nonce Reuse" or weak PRF if detectable.

## Proposed Changes (Phase 1 Detail)

### [internal/core/domain]

#### [MODIFY] [device.go](file:///home/llvch/Desktop/proyectos/wmap/internal/core/domain/device.go)
- Add `ObservedSSIDs []string` or `map[string]time.Time` to `Device` struct.

### [internal/adapters/sniffer/parser]

#### [MODIFY] [packet_handler.go](file:///home/llvch/Desktop/proyectos/wmap/internal/adapters/sniffer/parser/packet_handler.go)
- In `handleMgmtFrame`, when handling `Dot11TypeMgmtProbeResp`, update `device.ObservedSSIDs`.

### [internal/core/services/security]

#### [MODIFY] [detectors.go](file:///home/llvch/Desktop/proyectos/wmap/internal/core/services/security/detectors.go)
- Rename existing `KarmaDetector` to `ClientKarmaDetector` for clarity.
- Create `APKarmaDetector` to implement the logic described above.

## Verification Plan

### Automated Tests
- Create unit tests in `detectors_test.go` simulating an AP device with multiple `ObservedSSIDs` and verifying alert generation.
- Test `packet_handler` ensures SSIDs are accumulated.

### Manual Verification
- This requires simulating a Karma attack (e.g., using `hostapd-mana` or similar) and verifying `wmap` flags it. A simulated test case in Go is preferred.
