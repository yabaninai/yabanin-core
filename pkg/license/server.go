package license

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

// Server loads + periodically re-verifies the license token, exposing State.
type Server struct {
	tokenPath string
	mu        sync.RWMutex
	state     State
	stop      chan struct{}
}

// NewServer reads the token at tokenPath, verifies it, and starts a 1h
// re-verification goroutine. If tokenPath is empty, returns inactive state.
func NewServer(tokenPath string) *Server {
	s := &Server{tokenPath: tokenPath, stop: make(chan struct{})}
	s.refresh()
	go s.loop()
	return s
}

func (s *Server) loop() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.refresh()
		case <-s.stop:
			return
		}
	}
}

func (s *Server) refresh() {
	if s.tokenPath == "" {
		s.mu.Lock()
		s.state = State{}
		s.mu.Unlock()
		return
	}
	data, err := os.ReadFile(s.tokenPath)
	if err != nil {
		s.mu.Lock()
		s.state = State{}
		s.mu.Unlock()
		return
	}
	claims, err := Verify(string(data))
	if err != nil {
		s.mu.Lock()
		s.state = State{}
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	s.state = StateFromClaims(claims)
	s.mu.Unlock()
}

// State returns the current license state (safe for concurrent reads).
func (s *Server) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Handler returns GET /healthz/license JSON state.
func (s *Server) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.State())
	}
}

// Close stops the background re-verification goroutine.
func (s *Server) Close(_ context.Context) {
	close(s.stop)
}
