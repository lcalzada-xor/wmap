package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lcalzada-xor/wmap/internal/app"
	"github.com/lcalzada-xor/wmap/internal/config"
	"github.com/lcalzada-xor/wmap/internal/telemetry"
)

func main() {
	// Setup Structured Logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// load config
	cfg := config.Load()

	// Initialize Tracing
	shutdownTracer, err := telemetry.InitTracer()
	if err != nil {
		slog.Error("Failed to init tracer", "error", err)
	} else {
		defer func() {
			if err := shutdownTracer(context.Background()); err != nil {
				slog.Error("Failed to shutdown tracer", "error", err)
			}
		}()
	}

	// Initialize Application
	application, err := app.New(cfg)
	if err != nil {
		slog.Error("Failed to initialize application", "error", err)
		os.Exit(1)
	}

	// Root Context with cancellation on Interrupt
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("WMAP Starting...")

	// Restore network on exit
	defer application.RestoreNetwork()

	// Run Application
	if err := application.Run(ctx); err != nil {
		slog.Error("Application error", "error", err)
		cancel()
	}
}
