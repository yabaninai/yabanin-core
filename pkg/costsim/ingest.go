package audit

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// IngestOptions controls how a file is read into records.
type IngestOptions struct {
	// Format selects the parser: "auto" (default), "openai-jsonl", "jsonl"
	// (OpenAI shape with gateway-line fallback), "csv", "yabanin"/"tokenrouter"
	// (native export; sniffed CSV or JSONL), or the explicit "yabanin-csv" /
	// "tokenrouter-csv". Empty means "auto".
	Format string
	// MaxRecords caps the number of records ingested (default DefaultMaxRecords).
	MaxRecords int
	// NoPrompts drops the raw prompt text immediately after the hash is
	// computed, so a report can be shared without leaking content.
	NoPrompts bool
	// Provider, when non-empty, overrides provider inference for the whole file.
	Provider string
}

// DefaultMaxRecords is the default cap on ingested records.
const DefaultMaxRecords = 5_000_000

// maxReportedParseErrors caps the number of example parse errors surfaced in
// stats. All parse errors are still counted in ParseErrorCount.
const maxReportedParseErrors = 10

// IngestStats is the data-quality account returned alongside the records.
type IngestStats struct {
	// Parsed is the number of records returned.
	Parsed int
	// ParseErrorCount is the total number of lines that failed to parse and
	// were skipped.
	ParseErrorCount int
	// ParseErrorExamples holds up to maxReportedParseErrors example messages.
	ParseErrorExamples []string
	// WasSymlink reports whether the input path was a symlink (reported, not
	// silently followed).
	WasSymlink bool
	// WasTruncated reports whether MaxRecords capped the run before EOF.
	WasTruncated bool
	// Cap is the effective MaxRecords the run used (the default when the
	// caller passed 0). Exposed so a report can state the denominator cap.
	Cap int
	// RealTokenCount is the number of records whose token counts were taken
	// from the input rather than estimated from text length.
	RealTokenCount int
	// TimestampedCount is the number of records with a non-zero timestamp.
	TimestampedCount int
}

// Ingest reads the file at path and returns the parsed records plus a
// data-quality account. It never aborts the run because of a malformed line;
// such lines increment ParseErrorCount and are skipped. The whole file is
// never read into memory at once — it is streamed line by line.
func Ingest(ctx context.Context, path string, opts IngestOptions) ([]Record, IngestStats, error) {
	var wasSymlink bool
	if info, err := os.Lstat(path); err == nil {
		wasSymlink = info.Mode()&os.ModeSymlink != 0
	}

	f, err := os.Open(path) //nolint:gosec // path is operator-provided; they own the file
	if err != nil {
		return nil, IngestStats{}, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()

	records, stats, err := IngestReader(ctx, f, path, opts)
	if err != nil {
		return nil, IngestStats{}, err
	}

	stats.WasSymlink = wasSymlink
	return records, stats, nil
}

// --- JSONL (openai-jsonl and tokenrouter) ---------------------------------

func (b *ingestBatch) readJSONL(ctx context.Context, scanner *bufio.Scanner, parse func(string) (Record, error)) error {
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		b.add(parse(line))
		if b.stats.WasTruncated {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	return nil
}

// openAIRequest is the subset of an OpenAI chat-completions body we read.
type openAIRequest struct {
	Model       string   `json:"model"`
	MaxTokens   int      `json:"max_tokens"`
	Temperature *float64 `json:"temperature"`
	Messages    []struct {
		Content string `json:"content"`
	} `json:"messages"`
}

// openAIUsage mirrors the usage object.
type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// openAIResponse is the subset of a response we read (for wrapped + flat).
type openAIResponse struct {
	Usage openAIUsage `json:"usage"`
}

// parseOpenAIJSONLLine parses one openai-jsonl line in either the wrapped
// ({"request":...,"response":...}) or the flat (request body + usage at top
// level) shape.
func parseOpenAIJSONLLine(line string) (Record, error) {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &generic); err != nil {
		return Record{}, fmt.Errorf("invalid json: %v", err)
	}

	var req openAIRequest
	var resp openAIResponse
	var usage openAIUsage
	var ts time.Time
	var durationMS int
	var statusCode int

	// Wrapped shape: request/response objects nested.
	if raw, ok := generic["request"]; ok {
		_ = json.Unmarshal(raw, &req)
	}
	if raw, ok := generic["response"]; ok {
		_ = json.Unmarshal(raw, &resp)
	}
	// Flat shape: the request fields sit at the top level alongside usage.
	if _, hasReq := generic["request"]; !hasReq {
		_ = json.Unmarshal([]byte(line), &req)
	}
	if raw, ok := generic["usage"]; ok {
		_ = json.Unmarshal(raw, &usage)
	} else if resp.Usage.PromptTokens != 0 || resp.Usage.CompletionTokens != 0 {
		usage = resp.Usage
	}

	if raw, ok := generic["timestamp"]; ok {
		_ = json.Unmarshal(raw, &tsRaw{ts: &ts})
	}
	if raw, ok := generic["duration_ms"]; ok {
		_ = json.Unmarshal(raw, &durationMS)
	}
	if raw, ok := generic["status_code"]; ok {
		_ = json.Unmarshal(raw, &statusCode)
	}

	r := Record{
		Model:      req.Model,
		Timestamp:  ts,
		DurationMS: durationMS,
		StatusCode: statusCode,
		MaxTokens:  req.MaxTokens,
	}
	if req.Temperature != nil {
		r.Temperature = *req.Temperature
		r.TemperatureSet = true
	}
	// Concatenate message content into the prompt.
	var sb strings.Builder
	for _, m := range req.Messages {
		sb.WriteString(m.Content)
		sb.WriteString("\n")
	}
	r.Prompt = sb.String()

	// Token counts: prefer the usage object, else estimate from prompt text.
	if usage.PromptTokens > 0 || usage.CompletionTokens > 0 {
		r.PromptTokens = usage.PromptTokens
		r.CompletionTokens = usage.CompletionTokens
	} else if r.Prompt != "" {
		r.PromptTokens = EstimateTokens(r.Prompt)
		r.TokensEstimated = true
	}
	return r, nil
}

// tsRaw is a helper to unmarshal a time.Time from a json.RawMessage.
type tsRaw struct{ ts *time.Time }

func (t *tsRaw) UnmarshalJSON(b []byte) error {
	// Accept RFC3339; trim quotes.
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		return nil
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Keep zero value; the analyzer treats it as unordered.
		return nil //nolint:nilerr // malformed timestamp is not fatal: zero means unordered
	}
	*t.ts = parsed
	return nil
}

// parseTokenRouterLine parses one request_logs export line (JSONL shape).
// request_logs does not store prompt text, so Prompt stays empty and the
// token counts are the real gateway counts.
func parseTokenRouterLine(line string) (Record, error) {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &generic); err != nil {
		return Record{}, fmt.Errorf("invalid json: %v", err)
	}
	var modelUsed string
	if raw, ok := generic["model_used"]; ok {
		_ = json.Unmarshal(raw, &modelUsed)
	}
	var tokensIn, tokensOut, statusCode, durationMS int
	if raw, ok := generic["tokens_in"]; ok {
		_ = json.Unmarshal(raw, &tokensIn)
	}
	if raw, ok := generic["tokens_out"]; ok {
		_ = json.Unmarshal(raw, &tokensOut)
	}
	if raw, ok := generic["status_code"]; ok {
		_ = json.Unmarshal(raw, &statusCode)
	}
	if raw, ok := generic["duration_ms"]; ok {
		_ = json.Unmarshal(raw, &durationMS)
	}
	var ts time.Time
	if raw, ok := generic["created_at"]; ok {
		_ = json.Unmarshal(raw, &tsRaw{ts: &ts})
	}
	return Record{
		Model:            modelUsed,
		PromptTokens:     tokensIn,
		CompletionTokens: tokensOut,
		StatusCode:       statusCode,
		DurationMS:       durationMS,
		Timestamp:        ts,
	}, nil
}

// --- CSV (csv and tokenrouter-csv) ----------------------------------------

// knownCSVColumns are the recognized header names, mapped to canonical keys.
var knownCSVColumns = map[string]string{
	"timestamp":         "timestamp",
	"model":             "model",
	"model_used":        "model",
	"provider":          "provider",
	"prompt":            "prompt",
	"prompt_tokens":     "prompt_tokens",
	"tokens_in":         "prompt_tokens",
	"completion_tokens": "completion_tokens",
	"tokens_out":        "completion_tokens",
	"max_tokens":        "max_tokens",
	"temperature":       "temperature",
	"status_code":       "status_code",
	"duration_ms":       "duration_ms",
	"created_at":        "timestamp",
}

func (b *ingestBatch) readCSV(ctx context.Context, scanner *bufio.Scanner, prefix string) error {
	reader := csv.NewReader(&lineReader{s: scanner, pending: prefix})
	reader.FieldsPerRecord = -1 // header-driven; allow variable column counts

	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("read csv header: %w", err)
	}
	colIndex := map[string]int{}
	for i, name := range header {
		if key, ok := knownCSVColumns[strings.ToLower(strings.TrimSpace(name))]; ok {
			colIndex[key] = i
		}
	}
	if _, ok := colIndex["model"]; !ok {
		return fmt.Errorf("csv has no recognized model column (got %q)", header)
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read csv row: %w", err)
		}
		b.add(csvRowToRecord(row, colIndex))
		if b.stats.WasTruncated {
			break
		}
	}
	return nil
}

// csvRowToRecord maps a CSV row (via the resolved column index) to a Record.
func csvRowToRecord(row []string, idx map[string]int) (Record, error) {
	get := func(key string) string {
		i, ok := idx[key]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	getInt := func(key string) (int, error) {
		s := get(key)
		if s == "" {
			return 0, nil
		}
		return strconv.Atoi(s)
	}
	var r Record
	r.Model = get("model")
	r.Provider = get("provider")
	r.Prompt = get("prompt")
	var err error
	if r.PromptTokens, err = getInt("prompt_tokens"); err != nil {
		return Record{}, fmt.Errorf("prompt_tokens: %v", err)
	}
	if r.CompletionTokens, err = getInt("completion_tokens"); err != nil {
		return Record{}, fmt.Errorf("completion_tokens: %v", err)
	}
	if r.MaxTokens, err = getInt("max_tokens"); err != nil {
		return Record{}, fmt.Errorf("max_tokens: %v", err)
	}
	if r.StatusCode, err = getInt("status_code"); err != nil {
		return Record{}, fmt.Errorf("status_code: %v", err)
	}
	if r.DurationMS, err = getInt("duration_ms"); err != nil {
		return Record{}, fmt.Errorf("duration_ms: %v", err)
	}
	if s := get("temperature"); s != "" {
		if f, ferr := strconv.ParseFloat(s, 64); ferr == nil {
			r.Temperature = f
			r.TemperatureSet = true
		}
	}
	if s := get("timestamp"); s != "" {
		if t, terr := time.Parse(time.RFC3339, s); terr == nil {
			r.Timestamp = t
		}
	}
	// If no explicit counts but a prompt is present, estimate from text.
	if r.PromptTokens == 0 && r.CompletionTokens == 0 && r.Prompt != "" {
		r.PromptTokens = EstimateTokens(r.Prompt)
		r.TokensEstimated = true
	}
	return r, nil
}

// lineReader adapts a *bufio.Scanner to io.Reader so csv.NewReader can consume
// the remaining lines after the manually-read header. pending replays the line
// consumed by auto-format sniffing so the header is not lost.
type lineReader struct {
	s       *bufio.Scanner
	pending string
}

func (l *lineReader) Read(p []byte) (int, error) {
	if l.pending == "" {
		if !l.s.Scan() {
			if err := l.s.Err(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		l.pending = l.s.Text() + "\n"
	}
	n := copy(p, l.pending)
	l.pending = l.pending[n:]
	return n, nil
}
