package validation

import (
	"fmt"
	"net/http"
	"strings"
)

// CORSConfig holds CORS configuration for API endpoints.
type CORSConfig struct {
	AllowedOrigins   []string // empty = deny all (must be explicitly configured)
	AllowedMethods   []string // default: ["GET", "POST", "OPTIONS"]
	AllowedHeaders   []string // default: ["Content-Type", "Authorization", "X-Request-ID"]
	AllowCredentials bool
	MaxAge           int // preflight cache seconds, default 300
}

// DefaultCORS returns a restrictive CORS config — no origins allowed by default.
func DefaultCORS() CORSConfig {
	return CORSConfig{
		AllowedOrigins: nil, // must be explicitly set for production
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-Request-ID", "Accept", "Origin"},
		MaxAge:         300,
	}
}

// NewCORSMiddleware creates an HTTP middleware that enforces CORS policy.
func NewCORSMiddleware(cfg CORSConfig) func(http.Handler) http.Handler {
	allowedMethods := strings.Join(cfg.AllowedMethods, ",")
	allowedHeaders := strings.Join(cfg.AllowedHeaders, ",")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			if !isOriginAllowed(origin, cfg.AllowedOrigins) {
				// Strict: reject all CORS requests from unauthorized origins.
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			w.Header().Set("Vary", "Origin")

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isOriginAllowed(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if origin == a {
			return true
		}
	}
	return false
}
