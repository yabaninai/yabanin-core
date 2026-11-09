package tracing

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	otelhttp "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
)

// Globals.
var (
	tp   *sdktrace.TracerProvider
	mu   sync.Mutex
	once bool // tracks whether Init has been called (singleton guard)
)

// Init initializes the OpenTelemetry tracer provider with OTLP/HTTP transport.
// If endpoint is empty, a no-op tracer provider is configured and no spans are exported.
// The sampleRate controls the fraction of traces sampled (0.0–1.0; defaults to 0.1).
func Init(ctx context.Context, serviceName string, endpoint string, sampleRate float64) error {
	mu.Lock()
	defer mu.Unlock()

	if once {
		return nil
	}
	once = true

	// Apply defaults.
	if sampleRate <= 0 || sampleRate > 1 {
		sampleRate = 0.1
	}
	if serviceName == "" {
		serviceName = "unknown"
	}

	// No-op path: empty endpoint means no exporter, no spans exported.
	if endpoint == "" {
		return nil
	}

	// Build resource.
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
		),
	)
	if err != nil {
		return fmt.Errorf("tracing: failed to create resource: %w", err)
	}

	// Create OTLP/HTTP exporter.
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithTimeout(10*time.Second),
	)
	if err != nil {
		return fmt.Errorf("tracing: failed to create OTLP exporter: %w", err)
	}

	// Sampler with parent-based strategy so child spans inherit parent decision.
	sampler := sdktrace.ParentBased(
		sdktrace.TraceIDRatioBased(sampleRate),
	)

	// Batch span processor for efficient export.
	bsp := sdktrace.NewBatchSpanProcessor(exporter,
		sdktrace.WithBatchTimeout(5*time.Second),
		sdktrace.WithMaxExportBatchSize(512),
		sdktrace.WithMaxQueueSize(2048),
	)

	// TracerProvider with sampler + resource.
	tp = sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	// Register as global.
	otel.SetTracerProvider(tp)

	// Configure text map propagator for distributed context propagation.
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(propagator)

	return nil
}

// Tracer returns a named tracer from the global provider.
// Returns a no-op tracer if Init has not been called or endpoint was empty.
func Tracer(name string) trace.Tracer {
	if name == "" {
		name = "unknown"
	}
	return otel.Tracer(name)
}

// Shutdown flushes any pending spans and shuts down the tracer provider.
func Shutdown(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	if tp == nil {
		return nil
	}
	return tp.Shutdown(ctx)
}

// InjectSpanContext injects the current span's context into a map carrier (e.g. HTTP headers).
func InjectSpanContext(ctx context.Context, carrier propagation.TextMapCarrier) {
	propagator := otel.GetTextMapPropagator()
	if propagator != nil {
		propagator.Inject(ctx, carrier)
	}
}

// ExtractSpanContext extracts a span context from a map carrier.
func ExtractSpanContext(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	propagator := otel.GetTextMapPropagator()
	if propagator != nil {
		return propagator.Extract(ctx, carrier)
	}
	return ctx
}

// HTTPMiddleware returns a chi-compatible middleware that creates an HTTP server span
// for every incoming request using the otelhttp instrumentation. When tracing is not
// initialized (Init never called or endpoint empty), this returns a no-op middleware.
func HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, "")
	}
}

// WrapHandler wraps an existing http.Handler with otelhttp instrumentation.
// This is useful when the router is already constructed and you want to add tracing
// after the fact (e.g., in main.go after SetupRouter()).
func WrapHandler(h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, "")
}
