package regionrepl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Shipper POSTs rollup batches to the central analytics endpoint.
// Retries 3x with exponential backoff. Idempotent on the receiver (PK upsert).
type Shipper struct {
	endpoint     string
	client       *http.Client
	sourceRegion string
}

// NewShipper creates a rollup shipper that POSTs to the central analytics endpoint.
func NewShipper(endpoint, sourceRegion string) *Shipper {
	return &Shipper{
		endpoint:     endpoint,
		sourceRegion: sourceRegion,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

// Ship sends rows to ${endpoint}/internal/rollup-ingest as a JSON batch.
func (s *Shipper) Ship(ctx context.Context, rows []RollupRow) error {
	if len(rows) == 0 {
		return nil
	}
	payload := struct {
		Source string      `json:"source_region"`
		Rows   []RollupRow `json:"rows"`
	}{Source: s.sourceRegion, Rows: rows}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal rollups: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := s.postOnce(ctx, body); err == nil {
			return nil
		} else {
			lastErr = err
		}
		// exponential backoff: 1s, 2s, 4s
		select {
		case <-time.After(time.Duration(1<<attempt) * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("ship after 3 attempts: %w", lastErr)
}

func (s *Shipper) postOnce(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/internal/rollup-ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("central ingest status %d: %s", resp.StatusCode, string(snippet))
	}
	return nil
}
