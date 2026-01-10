.PHONY: build run test clean check-monitor

BINARY_NAME=wmap
BUILD_DIR=bin

build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/wmap

run: build
	@echo "Running $(BINARY_NAME)..."
	@sudo $(BUILD_DIR)/$(BINARY_NAME) -i wlan1

test:
	@echo "Running tests..."
	@go test ./... -v

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@rm -f *.db *.log *.pcap

# Utility to check if interface is in monitor mode
check-monitor:
	@iwconfig 2>&1 | grep Mode:Monitor
