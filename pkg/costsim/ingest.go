package audit

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// IngestOptions controls how a file is read into records.
type IngestOptions struct {
	// Format is "auto", "openai-jsonl", "csv", or "yabanin" (the native spend
	// export; the legacy alias "tokenrouter" is still accepted).
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
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = DefaultMaxRecords
	}
	if opts.Format == "" {
		opts.Format = "auto"
	}

	// Lstat (not Stat) so a symlinked input is reported rather than silently
	// followed. Stat follows the link and would report the target's mode.
	// Captured separately because the parser returns its own IngestStats.
	var wasSymlink bool
	if info, err := os.Lstat(path); err == nil {
		wasSymlink = info.Mode()&os.ModeSymlink != 0
	}

	f, err := os.Open(path) //nolint:gosec // path is operator-provided; they own the file
	if err != nil {
		return nil, IngestStats{}, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()

	// Enlarge the scanner buffer for long prompt lines.
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	// Determine the concrete format up front (auto sniffs extension + first
	// non-empty line, rewinding the stream to 0), then parse uniformly from the
	// start of the file.
	format, err := detectFormat(opts.Format, f, scanner)
	if err != nil {
		return nil, IngestStats{}, err
	}

	var records []Record
	var stats IngestStats
	addRecord := func(r Record) {
		if opts.Provider != "" {
			r.Provider = opts.Provider
		}
		records = append(records, r)
	}

	switch format {
	case "csv", "yabanin-csv", "tokenrouter-csv":
		records, stats, err = ingestCSV(scanner, format != "csv", opts, addRecord, ctx)
	case "openai-jsonl", "yabanin", "tokenrouter":
		records, stats, err = ingestJSONL(scanner, format != "openai-jsonl", opts, addRecord, ctx)
	default:
		return nil, IngestStats{}, fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return nil, IngestStats{}, err
	}

	// The parser returns a fresh IngestStats; re-attach the symlink flag we
	// captured before parsing and the effective cap used for the run.
	stats.WasSymlink = wasSymlink
	stats.Cap = opts.MaxRecords

	if opts.NoPrompts {
		for i := range records {
			records[i].Prompt = ""
		}
	}

	stats.Parsed = len(records)
	return records, stats, nil
}

// detectFormat resolves the concrete format. It leaves the file positioned at
// offset 0 (rewinding after any sniff) so the parser reads the whole file from
// the start.
func detectFormat(format string, f *os.File, scanner *bufio.Scanner) (string, error) {
	if format != "auto" {
		if format == "tokenrouter" {
			// tokenrouter may be CSV or JSONL; sniff the first line.
			if sniffTokenRouterKind(f, scanner) == "csv" {
				return "tokenrouter-csv", nil
			}
			return "tokenrouter", nil
		}
		return format, nil
	}

	// auto: sniff by extension first, then by first non-empty line.
	ext := strings.ToLower(filepath.Ext(f.Name()))
	switch ext {
	case ".csv":
		return "csv", nil
	case ".jsonl", ".json", ".ndjson":
		return "openai-jsonl", nil
	}
	// No telling extension: sniff the first non-empty line (stream rewound).
	first, err := firstNonEmptyLine(f, scanner)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(strings.TrimSpace(first), "{") {
		return "openai-jsonl", nil
	}
	return "csv", nil
}

// sniffTokenRouterKind reports whether a tokenrouter export is CSV ("csv") or
// JSONL ("jsonl"). It reads the first non-empty line without consuming the
// stream for the parser.
func sniffTokenRouterKind(f *os.File, scanner *bufio.Scanner) string {
	first, _ := firstNonEmptyLine(f, scanner)
	if strings.HasPrefix(strings.TrimSpace(first), "{") {
		return "jsonl"
	}
	return "csv"
}

// firstNonEmptyLine reads the first non-empty line, then rewinds the file to
// offset 0 so the caller can re-read it with the scanner.
func firstNonEmptyLine(f *os.File, scanner *bufio.Scanner) (string, error) {
	for scanner.Scan() {
		if line := scanner.Text(); strings.TrimSpace(line) != "" {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return "", fmt.Errorf("rewind input: %w", err)
			}
			return line, nil
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind input: %w", err)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}

// --- JSONL (openai-jsonl and tokenrouter) ---------------------------------

func ingestJSONL(scanner *bufio.Scanner, tokenRouter bool, opts IngestOptions, add func(Record), ctx context.Context) ([]Record, IngestStats, error) {
	var records []Record
	var stats IngestStats
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, stats, ctx.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r Record
		var parseErr error
		if tokenRouter {
			r, parseErr = parseTokenRouterLine(line)
		} else {
			r, parseErr = parseOpenAIJSONLLine(line)
		}
		if parseErr != nil {
			stats.ParseErrorCount++
			if len(stats.ParseErrorExamples) < maxReportedParseErrors {
				stats.ParseErrorExamples = append(stats.ParseErrorExamples, parseErr.Error())
			}
			continue
		}
		if r.Model == "" && r.Prompt == "" && r.PromptTokens == 0 && r.CompletionTokens == 0 {
			// A line that produced no usable signal is treated as unparseable
			// rather than a zero-valued record.
			stats.ParseErrorCount++
			if len(stats.ParseErrorExamples) < maxReportedParseErrors {
				stats.ParseErrorExamples = append(stats.ParseErrorExamples, "line carried no model, prompt, or token counts")
			}
			continue
		}
		if r.Provider == "" {
			r.Provider = InferProvider(r.Model)
		}
		if !r.TokensEstimated && (r.PromptTokens > 0 || r.CompletionTokens > 0) {
			stats.RealTokenCount++
		}
		if !r.Timestamp.IsZero() {
			stats.TimestampedCount++
		}
		add(r)
		records = append(records, r)
		if len(records) >= opts.MaxRecords {
			stats.WasTruncated = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("read input: %w", err)
	}
	return records, stats, nil
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

func ingestCSV(scanner *bufio.Scanner, _ bool, opts IngestOptions, add func(Record), ctx context.Context) ([]Record, IngestStats, error) {
	var records []Record
	var stats IngestStats

	reader := csv.NewReader(lineReader{scanner})
	reader.FieldsPerRecord = -1 // header-driven; allow variable column counts

	header, err := reader.Read()
	if err != nil {
		return nil, stats, fmt.Errorf("read csv header: %w", err)
	}
	colIndex := map[string]int{}
	for i, name := range header {
		if key, ok := knownCSVColumns[strings.ToLower(strings.TrimSpace(name))]; ok {
			colIndex[key] = i
		}
	}
	if _, ok := colIndex["model"]; !ok {
		return nil, stats, fmt.Errorf("csv has no recognized model column (got %q)", header)
	}

	for {
		if ctx.Err() != nil {
			return nil, stats, ctx.Err()
		}
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, stats, fmt.Errorf("read csv row: %w", err)
		}
		r, parseErr := csvRowToRecord(row, colIndex)
		if parseErr != nil {
			stats.ParseErrorCount++
			if len(stats.ParseErrorExamples) < maxReportedParseErrors {
				stats.ParseErrorExamples = append(stats.ParseErrorExamples, parseErr.Error())
			}
			continue
		}
		if r.Model == "" && r.Prompt == "" && r.PromptTokens == 0 && r.CompletionTokens == 0 {
			stats.ParseErrorCount++
			continue
		}
		if r.Provider == "" {
			r.Provider = InferProvider(r.Model)
		}
		if !r.TokensEstimated && (r.PromptTokens > 0 || r.CompletionTokens > 0) {
			stats.RealTokenCount++
		}
		if !r.Timestamp.IsZero() {
			stats.TimestampedCount++
		}
		add(r)
		records = append(records, r)
		if len(records) >= opts.MaxRecords {
			stats.WasTruncated = true
			break
		}
	}
	return records, stats, nil
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
// the remaining lines after the manually-read header.
type lineReader struct{ s *bufio.Scanner }

func (l lineReader) Read(p []byte) (int, error) {
	if !l.s.Scan() {
		if err := l.s.Err(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	line := l.s.Text() + "\n"
	if len(p) < len(line) {
		return 0, fmt.Errorf("buffer too small")
	}
	copy(p, line)
	return len(line), nil
}
