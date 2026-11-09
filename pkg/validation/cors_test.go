package validation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name             string
		origin           string
		method           string
		allowedOrigins   []string
		allowCredentials bool
		expectedStatus   int
		checkHeaders     func(t *testing.T, headers http.Header)
	}{
		{
			name:           "no origin header passes through without CORS headers",
			origin:         "",
			method:         "GET",
			allowedOrigins: nil,
			expectedStatus: http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Origin"); got != "" {
					t.Errorf("expected no Access-Control-Allow-Origin header, got %q", got)
				}
			},
		},
		{
			name:           "unauthorized origin is blocked",
			origin:         "https://evil.com",
			method:         "GET",
			allowedOrigins: []string{"https://example.com"},
			expectedStatus: http.StatusOK, // middleware returns with no body/status write; but httptest records 200 from empty write
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Origin"); got != "" {
					t.Errorf("expected no CORS headers for unauthorized origin, got Access-Control-Allow-Origin=%q", got)
				}
			},
		},
		{
			name:             "authorized origin gets CORS headers",
			origin:           "https://example.com",
			method:           "GET",
			allowedOrigins:   []string{"https://example.com"},
			allowCredentials: false,
			expectedStatus:   http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://example.com")
				}
				if got := h.Get("Access-Control-Allow-Methods"); got != "GET,POST,OPTIONS" {
					t.Errorf("Access-Control-Allow-Methods = %q, want %q", got, "GET,POST,OPTIONS")
				}
				if got := h.Get("Access-Control-Allow-Headers"); got == "" {
					t.Error("Access-Control-Allow-Headers should be set")
				}
				if got := h.Get("Vary"); got != "Origin" {
					t.Errorf("Vary = %q, want %q", got, "Origin")
				}
				if got := h.Get("Access-Control-Allow-Credentials"); got != "" {
					t.Errorf("expected no credentials header, got %q", got)
				}
			},
		},
		{
			name:             "OPTIONS preflight returns 200 with Max-Age",
			origin:           "https://example.com",
			method:           http.MethodOptions,
			allowedOrigins:   []string{"https://example.com"},
			allowCredentials: false,
			expectedStatus:   http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://example.com")
				}
				if got := h.Get("Access-Control-Max-Age"); got == "" {
					t.Error("Access-Control-Max-Age should be set for OPTIONS preflight")
				}
			},
		},
		{
			name:             "POST request with authorized origin includes CORS headers",
			origin:           "https://example.com",
			method:           http.MethodPost,
			allowedOrigins:   []string{"https://example.com"},
			allowCredentials: false,
			expectedStatus:   http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://example.com")
				}
			},
		},
		{
			name:             "credentials allowed sets Allow-Credentials header",
			origin:           "https://example.com",
			method:           "GET",
			allowedOrigins:   []string{"https://example.com"},
			allowCredentials: true,
			expectedStatus:   http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Credentials"); got != "true" {
					t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
				}
			},
		},
		{
			name:             "multiple origins each get echoed back",
			origin:           "https://another.com",
			method:           "GET",
			allowedOrigins:   []string{"https://example.com", "https://another.com"},
			allowCredentials: false,
			expectedStatus:   http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Origin"); got != "https://another.com" {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://another.com")
				}
			},
		},
		{
			name:             "multiple origins first origin works",
			origin:           "https://example.com",
			method:           "GET",
			allowedOrigins:   []string{"https://example.com", "https://another.com"},
			allowCredentials: false,
			expectedStatus:   http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				t.Helper()
				if got := h.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://example.com")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultCORS()
			cfg.AllowedOrigins = tt.allowedOrigins
			cfg.AllowCredentials = tt.allowCredentials

			middleware := NewCORSMiddleware(cfg)
			wrapped := middleware(handler)

			req := httptest.NewRequestWithContext(context.Background(), tt.method, "http://example.com/api", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			w := httptest.NewRecorder()
			wrapped.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.expectedStatus)
			}

			if tt.checkHeaders != nil {
				tt.checkHeaders(t, w.Header())
			}
		})
	}
}
