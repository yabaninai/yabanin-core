// Package mockopenai provides a reusable HTTP test server that mimics
// the OpenAI Chat Completions API. It records requests and returns
// configurable responses (JSON body, status code, SSE stream).
package mockopenai

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// Server is an httptest-like server for OpenAI-compatible mocking.
type Server struct {
	mu           sync.Mutex
	requests     []Request
	lastResponse Response
	callCount    int
	failFirstN   int
	failWith     FailAction
	streamMode   bool
}

// Request records what the client sent.
type Request struct {
	Method string
	URL    string
	Header http.Header
	Body   string
	Host   string
	Path   string
}

// Response configures what the server returns.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       string // raw JSON or SSE body
}

// FailAction controls how FailFirstN behaves.
type FailAction struct {
	Status  int    // HTTP status (e.g. 429)
	Message string // error message in response body
	Header  http.Header
}

// New starts a mock upstream server for tests.
// New.
func New() *Server {
	return &Server{
		lastResponse: Response{StatusCode: 200},
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.callCount++

	// Record the request before any early returns.
	req := Request{
		Method: r.Method,
		URL:    r.URL.String(),
		Header: r.Header.Clone(),
		Body:   "",
		Host:   r.Host,
		Path:   r.URL.Path,
	}

	// Handle fail-first-N logic.
	if s.failFirstN > 0 {
		s.failFirstN--
		if s.failWith.Status != 0 {
			for k, vv := range s.failWith.Header {
				w.Header()[k] = vv
			}
			w.WriteHeader(s.failWith.Status)
			if s.failWith.Message != "" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": s.failWith.Message})
			}
			bodyBytes, _ := io.ReadAll(r.Body)
			req.Body = string(bodyBytes)
			s.requests = append(s.requests, req)
			return
		}
	}

	resp := s.lastResponse
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	if _, ok := resp.Header["Content-Type"]; !ok {
		resp.Header["Content-Type"] = []string{"application/json"}
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)

	if s.streamMode && resp.Body != "" {
		chunks := splitSSE(resp.Body)
		flusher, _ := w.(http.Flusher)
		for i, chunk := range chunks {
			if chunk == "" {
				continue
			}
			if !hasDataPrefix(chunk) {
				chunk = "data: " + chunk
			}
			_, _ = w.Write([]byte(chunk + "\n\n"))
			if flusher != nil && i < len(chunks)-1 {
				flusher.Flush()
			}
		}
	} else if resp.Body != "" {
		_, _ = w.Write([]byte(resp.Body))
	}

	bodyBytes, _ := io.ReadAll(r.Body)
	req.Body = string(bodyBytes)

	s.requests = append(s.requests, req)
}

func splitSSE(body string) []string {
	var parts []string
	current := ""
	for _, line := range splitLines(body) {
		if line == "" && current != "" {
			parts = append(parts, current)
			current = ""
		} else {
			if current != "" {
				current += "\n"
			}
			current += line
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func splitLines(s string) []string {
	var lines []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			lines = append(lines, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func hasDataPrefix(s string) bool {
	return len(s) >= 5 && s[:5] == "data:"
}

// SetResponse configures the next response.
func (s *Server) SetResponse(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastResponse = Response{StatusCode: status, Body: body}
}

// SetStreamMode enables SSE streaming for subsequent responses.
func (s *Server) SetStreamMode(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamMode = enabled
}

// FailFirstN makes the next N calls return the given status code and message.
func (s *Server) FailFirstN(n int, status int, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failFirstN = n
	s.failWith = FailAction{Status: status, Message: msg}
}

// ResetFail clears fail-first-N state.
func (s *Server) ResetFail() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failFirstN = 0
	s.failWith = FailAction{}
}

// Requests returns a copy of recorded requests.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]Request, len(s.requests))
	copy(cp, s.requests)
	return cp
}

// CallCount returns how many times ServeHTTP was called.
func (s *Server) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCount
}
