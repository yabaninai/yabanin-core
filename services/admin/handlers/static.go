package handlers

import (
	"net/http"
	"path/filepath"
)

// serveStatic returns a handler that serves static files from the given filesystem.
// It maps URLs to files under "assets/" — e.g. /dashboard -> assets/dashboard.html.
func (h *AdminHandlers) serveStatic() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "" {
			path = "/index.html"
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case ".css":
			w.Header().Set("Content-Type", "text/css")
		case ".js":
			w.Header().Set("Content-Type", "application/javascript")
		case ".json":
			w.Header().Set("Content-Type", "application/json")
		case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp":
			w.Header().Set("Content-Type", "image/"+ext[1:])
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
		}

		http.FileServer(http.Dir("assets")).ServeHTTP(w, r)
	}
}
