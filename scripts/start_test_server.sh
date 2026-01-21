#!/bin/bash
set -e

# Resolve Project Root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

# Change to project root to ensure go run works
cd "$PROJECT_ROOT"

# Configuration
TEST_DIR="/tmp/wmap-test-env"
DB_PATH="$TEST_DIR/system.db"
WORKSPACE_DIR="$TEST_DIR/workspaces"

# Default scenario
MOCK_SCENARIO="${MOCK_SCENARIO:-basic}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --scenario=*)
            MOCK_SCENARIO="${1#*=}"
            shift
            ;;
        --help)
            echo "Usage: $0 [--scenario=SCENARIO]"
            echo ""
            echo "Scenarios:"
            echo "  basic      - 5 APs, 10 Stations (default)"
            echo "  crowded    - 20 APs, 50 Stations"
            echo "  attack     - 8 APs, 15 Stations with handshakes"
            echo "  vulnerable - 10 APs, 20 Stations with vulnerabilities"
            echo ""
            echo "Example: $0 --scenario=crowded"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "=== WMAP Test Server Launcher ==="
echo "Setting up test environment in $TEST_DIR..."
echo "Mock Scenario: $MOCK_SCENARIO"

# Cleanup previous run
rm -rf "$TEST_DIR"
mkdir -p "$WORKSPACE_DIR"
mkdir -p "$(dirname "$DB_PATH")"

# Seed a Demo Workspace
# Touching the file is enough as the app will auto-migrate schema on load
touch "$WORKSPACE_DIR/Demo_Workspace.db"
touch "$WORKSPACE_DIR/Pentest_Op_Alpha.db"

echo "Created seed workspaces: Demo_Workspace, Pentest_Op_Alpha"

# Export Environment Variables
export WMAP_MOCK=true
export WMAP_ADDR=":8081"
export WMAP_DB="$DB_PATH"
export WMAP_WORKSPACE_DIR="$WORKSPACE_DIR"
export WMAP_INTERFACE="mock0" # Dummy interface
export MOCK_SCENARIO="$MOCK_SCENARIO"

echo "Starting WMAP in MOCK MODE..."
echo "Access the UI at http://localhost:8081"
echo "Press Ctrl+C to stop."
echo ""

# Run the application
go run cmd/wmap/main.go
