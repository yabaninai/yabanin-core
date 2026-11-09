package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

const embeddingDim = 384

// EmbeddingRequest matches the OpenAI-compatible /v1/embeddings endpoint.
type EmbeddingRequest struct {
	Model string      `json:"model"`
	Input interface{} `json:"input"`
}

// EmbeddingData is a single result from the embedding service.
type EmbeddingData struct {
	Embedding []float32 `json:"embedding"`
	Index     int       `json:"index"`
	Object    string    `json:"object"`
}

// EmbeddingResponse is returned by the /v1/embeddings endpoint.
type EmbeddingResponse struct {
	Data  []EmbeddingData `json:"data"`
	Model string          `json:"model"`
	Usage Usage           `json:"usage"`
}

// Usage contains token usage information.
type Usage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

func main() {
	port := os.Getenv("MOCK_EMBEDDER_PORT")
	if port == "" {
		port = "6006"
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	http.HandleFunc("/v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req EmbeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		// Handle both string and []string inputs.
		var texts []string
		switch v := req.Input.(type) {
		case string:
			texts = []string{v}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					texts = append(texts, s)
				}
			}
		default:
			http.Error(w, "unsupported input type", http.StatusBadRequest)
			return
		}

		if len(texts) == 0 {
			http.Error(w, "no inputs provided", http.StatusBadRequest)
			return
		}

		data := make([]EmbeddingData, len(texts))
		for i, text := range texts {
			data[i] = EmbeddingData{
				Index:     i,
				Object:    "embedding",
				Embedding: deterministicEmbedding(text),
			}
		}

		resp := EmbeddingResponse{
			Data:  data,
			Model: req.Model,
			Usage: Usage{PromptTokens: len(texts) * 10, TotalTokens: len(texts) * 10},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	addr := ":" + port
	log.Printf("mock-embedder listening on %s (dim=%d)", addr, embeddingDim)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// deterministicEmbedding generates a reproducible 384-dim vector from the input text.
// This ensures that the same prompt always produces the same embedding, enabling
// exact-match cache hits without needing a real ML model.
func deterministicEmbedding(text string) []float32 {
	hash := sha256.Sum256([]byte(text))
	v := make([]float32, embeddingDim)
	for i := 0; i < embeddingDim; i++ {
		// Use pairs of hash bytes to get a signed float in [-1, 1].
		b1 := int(hash[i%32])
		b2 := int(hash[(i+1)%32])
		val := float32((b1+b2)&0xFF)/128.0 - 1.0
		v[i] = val
	}

	// Normalize to unit vector (cosine similarity requires this).
	var sumSq float64
	for _, f := range v {
		sumSq += float64(f * f)
	}
	if sumSq > 0 {
		norm := float64(sumSq)
		for i := range v {
			v[i] = float32(float64(v[i]) / norm)
		}
	}

	return v
}
