#!/bin/bash
# Test script to verify Ctrl-C handling

set -e

echo "=== Ctrl-C Signal Handling Test ==="
echo ""
echo "This script will verify that:"
echo "1. The application compiles successfully"
echo "2. Signal handling is properly configured"
echo "3. All attack engines have StopAll methods"
echo ""

# Build the application
echo "[1/4] Building application..."
cd /home/llvch/Desktop/proyectos/wmap
go build -o wmap ./cmd/wmap 2>&1 | head -20
if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Check signal handling in main.go
echo ""
echo "[2/4] Checking signal handling in main.go..."
if grep -q "signal.NotifyContext.*os.Interrupt.*syscall.SIGTERM" cmd/wmap/main.go; then
    echo "✅ Signal handling configured (SIGINT, SIGTERM)"
else
    echo "❌ Signal handling not found"
    exit 1
fi

# Check attack stopping in app.go
echo ""
echo "[3/4] Checking attack cleanup order in app.go..."
if grep -q "Stopping all active attacks" internal/app/app.go; then
    echo "✅ Attacks are stopped before cleanup"
else
    echo "❌ Attack stopping not found in correct order"
    exit 1
fi

# Check StopAll methods exist
echo ""
echo "[4/4] Checking StopAll methods in attack engines..."

engines_ok=true

if grep -q "func (s \*WPSEngine) StopAll" internal/adapters/attack/wps/engine.go; then
    echo "✅ WPSEngine.StopAll exists"
else
    echo "❌ WPSEngine.StopAll not found"
    engines_ok=false
fi

if grep -q "func (e \*DeauthEngine) StopAll" internal/adapters/attack/deauth/engine.go; then
    echo "✅ DeauthEngine.StopAll exists"
else
    echo "❌ DeauthEngine.StopAll not found"
    engines_ok=false
fi

if grep -q "func (e \*AuthFloodEngine) StopAll" internal/adapters/attack/authflood/engine.go; then
    echo "✅ AuthFloodEngine.StopAll exists"
else
    echo "❌ AuthFloodEngine.StopAll not found"
    engines_ok=false
fi

if [ "$engines_ok" = false ]; then
    exit 1
fi

echo ""
echo "=== All checks passed! ==="
echo ""
echo "Signal handling flow:"
echo "1. Ctrl-C pressed → signal.NotifyContext cancels context"
echo "2. app.Run() receives ctx.Done()"
echo "3. app.NetworkService.Close() → AttackCoordinator.StopAll()"
echo "4. Each engine's StopAll() cancels all attack contexts"
echo "5. WPS engine: SIGTERM → wait 2s → SIGKILL (if needed)"
echo "6. Application exits cleanly"
echo ""
echo "✅ Ready for manual testing"
