# Mock Data System for Frontend Development

This package provides a complete mock data system for testing the WMAP frontend without requiring real WiFi hardware or packet capture capabilities.

## Overview

The mock system generates realistic WiFi network data including:
- Access Points (APs) with various security configurations
- Stations (STAs) connected to APs or probing
- Real-time events (handshakes, vulnerabilities, logs)
- Attack simulations (Deauth, WPS, Auth Flood)

## Components

### 1. Data Generator (`data_generator.go`)

Generates realistic mock devices with:
- **MAC Addresses**: Based on real vendor OUI prefixes
- **SSIDs**: Common network names
- **Channels**: Proper 2.4GHz (1-13) and 5GHz (36-165) channels
- **Security**: WPA2, WPA3, WEP, OPEN
- **Vendors**: Apple, Samsung, Cisco, TP-Link, etc.
- **Device Names**: iPhone, MacBook, Samsung Galaxy, etc.

### 2. WebSocket Server (`websocket_server.go`)

Simulates real-time data updates:
- **Graph Updates**: Sends device/network state every 4 seconds
- **Events**: Random handshakes, vulnerabilities, anomalies
- **Logs**: System messages and status updates
- **Attack Responses**: Simulates WPS/Deauth attack feedback

## Usage

### Starting the Mock Server

```bash
# Basic scenario (5 APs, 10 Stations)
./scripts/start_test_server.sh

# Or with custom scenario
MOCK_SCENARIO=crowded ./scripts/start_test_server.sh
```

### Available Scenarios

- **basic** (default): 5 APs, 10 Stations - Good for testing basic functionality
- **crowded**: 20 APs, 50 Stations - Stress test with many devices
- **attack**: 8 APs, 15 Stations - Some handshakes pre-captured
- **vulnerable**: 10 APs, 20 Stations - Networks with WEP/WPS vulnerabilities

### Environment Variables

```bash
export WMAP_MOCK=true              # Enable mock mode
export WMAP_ADDR=":8081"           # Server address
export MOCK_SCENARIO="basic"       # Scenario to use
```

## Mock Data Characteristics

### Access Points
- **SSID**: Randomly selected from common names
- **Channel**: Realistic distribution (60% 2.4GHz, 40% 5GHz)
- **Security**: Weighted (60% WPA2, 20% WPA3, 5% WEP, 15% OPEN)
- **WPS**: 30% have WPS enabled
- **Hidden**: 10% are hidden networks
- **RSSI**: -30 to -70 dBm

### Stations
- **Connection**: 80% connected, 20% probing
- **RSSI**: -40 to -90 dBm
- **Vendors**: Mobile device vendors (Apple, Samsung, Google, etc.)
- **Device Names**: Realistic device identifiers

### Dynamic Behavior

The mock system simulates network activity:
- **New Devices**: 10% chance every update cycle
- **Device Removal**: 5% chance (minimum 5 devices maintained)
- **RSSI Changes**: ±5 dBm to simulate movement
- **Packet Counts**: Incrementing counters

## WebSocket Messages

### Graph Update
```json
{
  "type": "graph",
  "payload": {
    "nodes": [...],
    "edges": [...]
  }
}
```

### Log Message
```json
{
  "type": "log",
  "payload": {
    "message": "New device detected: AA:BB:CC:DD:EE:FF",
    "level": "info"
  }
}
```

### Alert
```json
{
  "type": "alert",
  "payload": {
    "type": "HANDSHAKE_CAPTURED",
    "details": "SSID: HomeNetwork, BSSID: AA:BB:CC:DD:EE:FF"
  }
}
```

### WPS Status
```json
{
  "type": "wps.status",
  "payload": {
    "status": "running",
    "message": "WPS PIN attempt 3/5"
  }
}
```

## Development Workflow

1. **Start Mock Server**:
   ```bash
   ./scripts/start_test_server.sh
   ```

2. **Access Frontend**:
   Open `http://localhost:8081` in your browser

3. **Auto-Login**:
   In mock mode, authentication is bypassed (auto-login as "mock_user")

4. **Test Features**:
   - Graph visualization with mock devices
   - Filters and search
   - Attack panels (simulated responses)
   - Real-time updates
   - Vulnerability detection

## Testing Different Scenarios

```bash
# Test with many devices (performance testing)
MOCK_SCENARIO=crowded ./scripts/start_test_server.sh

# Test vulnerability detection
MOCK_SCENARIO=vulnerable ./scripts/start_test_server.sh

# Test with active attacks
MOCK_SCENARIO=attack ./scripts/start_test_server.sh
```

## Extending the Mock System

### Adding New Device Types

Edit `seed_data.go` or `data_generator.go`:
```go
var deviceNames = []string{
    "Your Device Name",
    // ...
}
```

### Adding New Events

Edit `websocket_server.go` in `sendRandomEvent()`:
```go
case 3:
    msg = map[string]interface{}{
        "type": "your_event",
        "payload": map[string]interface{}{
            // Your event data
        },
    }
```

### Customizing Scenarios

Modify `GenerateScenario()` in `data_generator.go`:
```go
case "your_scenario":
    numAPs = 15
    numStations = 30
    // Custom logic
```

## Limitations

- No actual packet capture
- No real attack execution
- Simplified network topology
- Fixed update intervals
- No persistence between restarts

## Troubleshooting

### Mock server not starting
- Check `WMAP_MOCK=true` is set
- Verify port 8081 is available
- Check logs for errors

### No devices appearing
- Wait 4-5 seconds for first update
- Check browser console for WebSocket connection
- Verify WebSocket endpoint `/ws` is accessible

### Frontend errors
- Clear browser cache
- Check for JavaScript errors in console
- Verify all static files are served correctly

## Future Enhancements

- [ ] Configurable update intervals
- [ ] More realistic traffic patterns
- [ ] Simulated channel hopping
- [ ] Mock GPS coordinates
- [ ] Persistent mock data between restarts
- [ ] API to control mock behavior from frontend
