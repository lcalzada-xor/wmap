package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
)

// InitTracer initializes the OpenTelemetry tracer provider.
// It returns a shutdown function that should be called on app exit.
func InitTracer() (func(context.Context) error, error) {
	// Create a stdout exporter to print traces to console (for development)
	// In production, you would replace this with an OTLP exporter.
	// We configure it to print nicely formatted JSON.
	exporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
	)
	if err != nil {
		return nil, err
	}

	// Create a resource describing this service
	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceName("wmap"),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create and register the TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	// Set global propagator to tracecontext (standard W3C)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Return global shutdown function
	return tp.Shutdown, nil
}
